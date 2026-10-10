package net.rafalohaki.veloauth.dialog;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.command.DialogAuthBridge;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.i18n.MinecraftLocales;
import net.rafalohaki.veloauth.util.FloodgateDetector;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * GUI authentication for Minecraft 1.21.6+ clients (protocol 771 … 777 / 26.3).
 *
 * <p>Life cycle of one connection:
 * <ol>
 *   <li>{@code PostLoginEvent}: the listener asks {@link #shouldHandle(Player)} and, when positive,
 *       prepares the session with {@link #begin(Player)} (click listener only, nothing shown).
 *       The player then takes VeloAuth's regular unauthenticated route to the auth server.</li>
 *   <li>{@code ServerConnectedEvent} on the auth server: a short "checking your account" action
 *       bar, then - depending on the database - the login or the registration form, in the
 *       client's language ({@link MinecraftLocales}). Clicks are executed through
 *       {@link DialogAuthBridge}, i.e. by the very same code the chat commands use (brute-force
 *       limits, IP limits, BCrypt, 2FA, audit…).</li>
 *   <li>On success VeloAuth's own post-auth flow transfers the player to the backend (as after
 *       {@code /login}); errors re-open the form behind a localized notice; the exit button and the
 *       timeouts disconnect the player. Typed commands / chat bring the form back.</li>
 *   <li>Premium nick without a record: the ownership check (action bar + Mojang profile key) and
 *       the "pick another name" notice run on the same auth server.</li>
 * </ol>
 */
public final class DialogAuthService {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final long KEEP_ALIVE_SECONDS = 10L;
    private static final long LOCALE_POLL_MILLIS = 50L;
    private static final int INPUT_WIDTH = 200;
    private static final int BUTTON_WIDTH = 150;
    private static final int BODY_WIDTH = 250;
    private static final int MAX_PENDING_CLICKS = 4;
    private static final String BRUTE_FORCE_BLOCKED_KEY = "security.brute_force.blocked";
    private final com.github.benmanes.caffeine.cache.Cache<String, String> recentLanguages =
            com.github.benmanes.caffeine.cache.Caffeine.newBuilder()
                    .maximumSize(10_000)
                    .expireAfterWrite(java.time.Duration.ofHours(6))
                    .build();
    private static final int NOTICE_TIMEOUT_SECONDS = 30;
    private static final String PREMIUM_NAME_KICK_KEY = "connection.premium_name.kick";
    /** Kick after the notice: "Kicked from {0}" with the configured network name. */
    private static final String PREMIUM_NAME_KICKED_KEY = "connection.premium_name.kicked";
    private static final long ACTION_BAR_REFRESH_MILLIS = 1000L;
        private static final int NOTICE_BUTTON_WIDTH = 150;

    private enum Form { LOGIN, REGISTER, TOTP }

    private final VeloAuth plugin;
    private final ProxyServer server;
    private final Logger logger;
    private final Settings settings;
    private final Messages messages;
    private final VelocityDialogTransport transport;
    private final DialogAuthBridge bridge;
    private final ConcurrentHashMap<UUID, Session> sessions = new ConcurrentHashMap<>();
    private final Set<UUID> authenticatedPreJoin = ConcurrentHashMap.newKeySet();
    /** Connections that used a dialog (form, check or notice): no plugin chat lines for them. */
    private final Set<UUID> dialogConnections = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean closed = new AtomicBoolean();

    public DialogAuthService(VeloAuth plugin, Settings settings, Messages messages,
                             VelocityDialogTransport transport, DialogAuthBridge bridge) {
        this.plugin = plugin;
        this.server = plugin.getServer();
        this.logger = plugin.getLogger();
        this.settings = settings;
        this.messages = messages;
        this.transport = transport;
        this.bridge = bridge;
    }

    // ------------------------------------------------------------------ public API

    /** Whether the feature is switched on and the proxy supports it. */
    public boolean isEnabled() {
        return !closed.get() && settings.getDialogSettings().isEnabled() && transport.isAvailable();
    }

    /**
     * Decides whether this freshly logged-in connection should authenticate through a dialog.
     * Premium (Mojang-verified) and Floodgate players never need it; clients older than 1.21.6
     * cannot display dialogs and keep the classic flow.
     */
    public boolean shouldHandle(Player player) {
        if (!isEnabled() || player == null || !player.isActive()) {
            return false;
        }
        if (player.isOnlineMode()) {
            return false;
        }
        if (FloodgateDetector.isBedrockPlayer(player.getUniqueId())) {
            return false;
        }
        if (bridge.isAuthenticated(player)) {
            return false;
        }
        return transport.supports(player);
    }

    /**
     * Prepares the dialog session for a cracked connection. Nothing is shown yet: the player is
     * routed by VeloAuth's regular unauthenticated flow to the auth server (the waiting place) and
     * {@link #onServerConnected} opens the login / register form there, exactly where the
     * premium-name notice appears. The click listener is attached now so no click can be missed.
     * The returned future completes when the session ends.
     */
    public CompletableFuture<Void> begin(Player player) {
        Session session = new Session(player);
        Session previous = sessions.put(player.getUniqueId(), session);
        if (previous != null) {
            previous.finish();
        }
        if (!transport.attachClickListener(player, click -> onClick(session, click))) {
            logger.warn(AUTH_MARKER, "Dialog login unavailable for {} - falling back to the auth server flow",
                    player.getUsername());
            session.finish();
            return session.done;
        }
        markDialogConnection(player);
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Dialog session prepared for {} - form opens on the auth server",
                    player.getUsername());
        }
        return session.done;
    }

    /** The GUI replaces chat: plugin/auth-server chat lines are filtered until the backend. */
    private void markDialogConnection(Player player) {
        dialogConnections.add(player.getUniqueId());
        transport.muteChat(player);
    }

    /** True while the player has an open login / register form session (not a notice). */
    public boolean isFormSession(UUID playerId) {
        Session session = playerId == null ? null : sessions.get(playerId);
        return session != null && !session.noticeOnly && session.premiumCheck == null && !session.finished.get();
    }

    /**
     * Re-opens the current form after the player typed a command or chat message instead of
     * using the dialog. A player who meanwhile authenticated (e.g. via {@code /login}) ends the
     * session; VeloAuth's own post-auth flow transfers them.
     */
    public void reshowForm(UUID playerId) {
        Session session = playerId == null ? null : sessions.get(playerId);
        if (session == null || session.noticeOnly || session.premiumCheck != null
                || session.finished.get() || !session.formShown) {
            return;
        }
        if (bridge.isAuthenticated(session.player)) {
            transport.clear(session.player);
            session.finish();
            return;
        }
        runAsync(session, () -> showForm(session, session.form));
    }

    /** Auth-server arrival of a prepared form session: the form opens immediately. */
    private void startFormInPlay(Session session) {
        Player player = session.player;
        if (session.finished.get() || !player.isActive()) {
            return;
        }
        if (bridge.isAuthenticated(player)) {
            session.finish(); // session auto-login etc. - VeloAuth transfers the player itself
            return;
        }
        session.language = resolveLanguage(player);
        rememberLanguage(player, session.language);
        session.timeoutTask = server.getScheduler()
                .buildTask(plugin, () -> onTimeout(session))
                .delay(settings.getDialogSettings().getTimeoutSeconds(), TimeUnit.SECONDS)
                .schedule();
        runAsync(session, () -> showInitialForm(session));
    }

    /**
     * True when this player can receive dialogs at all (1.21.6+ Java client in CONFIGURATION),
     * regardless of authentication state.
     */
    public boolean supportsDialogs(Player player) {
        // Independent of dialog.format: notices are shown as a GUI even in chat_system mode.
        return !closed.get() && transport.isAvailable() && player != null && player.isActive()
                && !FloodgateDetector.isBedrockPlayer(player.getUniqueId())
                && transport.supports(player);
    }

    /**
     * Shows a localized "this nickname belongs to a premium account" notice and disconnects the
     * player when they acknowledge it (or after a short timeout). The connection is never
     * authenticated; the returned future completes when the player is gone.
     */
    public CompletableFuture<Void> showPremiumNameNotice(Player player) {
        Session session = new Session(player);
        session.noticeOnly = true;
        Session previous = sessions.put(player.getUniqueId(), session);
        if (previous != null) {
            previous.finish();
        }
        if (!transport.attachClickListener(player, click -> onClick(session, click))) {
            disconnect(session, PREMIUM_NAME_KICK_KEY, player.getUsername());
            return session.done;
        }
        session.keepAliveTask = server.getScheduler()
                .buildTask(plugin, () -> transport.keepAlive(player))
                .delay(KEEP_ALIVE_SECONDS, TimeUnit.SECONDS)
                .repeat(KEEP_ALIVE_SECONDS, TimeUnit.SECONDS)
                .schedule();
        session.timeoutTask = server.getScheduler()
                .buildTask(plugin, () -> disconnect(session, PREMIUM_NAME_KICK_KEY, player.getUsername()))
                .delay(NOTICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .schedule();
        long deadline = System.nanoTime()
                + TimeUnit.MILLISECONDS.toNanos(settings.getDialogSettings().getLocaleWaitMillis());
        resolveLanguageThenShow(session, deadline);
        return session.done;
    }

    // ------------------------------------------------------------------ premium ownership check

    /**
     * Starts the premium-nick ownership check for an offline connection whose nickname belongs to
     * a Mojang account that has no VeloAuth record yet. Called from PostLogin (CONFIGURATION):
     * the listener is attached now so the client's profile-key packet - sent right after it
     * enters PLAY on the auth server - cannot be missed. Velocity then routes the player to the
     * auth server as usual; once there a centred "checking your account" dialog is shown, and
     * after at most {@code dialog.premium-name-notice.check-seconds}:
     * <ul>
     *   <li>a Mojang-signed profile key for exactly {@code premiumUuid} was seen → the connection
     *       is proven to belong to the premium owner: {@code onVerified} runs (the listener
     *       re-admits the player through the normal Mojang-verified premium flow);</li>
     *   <li>otherwise → cracked client: the localized "pick another name" notice, button → kick.</li>
     * </ul>
     * Nothing is ever authenticated inside this session.
     */
    public CompletableFuture<Void> beginPremiumCheck(Player player, UUID premiumUuid, Runnable onVerified) {
        Session session = new Session(player);
        session.noticeOnly = true;
        PremiumCheck check = new PremiumCheck(premiumUuid, onVerified);
        session.premiumCheck = check;
        Session previous = sessions.put(player.getUniqueId(), session);
        if (previous != null) {
            previous.finish();
        }
        boolean attached = transport.attachClickListener(player,
                click -> onClick(session, click),
                raw -> onRawPacket(session, raw));
        if (!attached) {
            disconnect(session, PREMIUM_NAME_KICK_KEY, player.getUsername());
            return session.done;
        }
        markDialogConnection(player);
        // 26.2+ clients send their Mojang profile key only when Login(play) says onlineMode=true;
        // Velocity fills that flag from the (offline) connection, so it is rewritten for this check.
        transport.forceOnlineModeInJoinGame(player);
        int checkSeconds = Math.max(1, settings.getDialogSettings().getPremiumCheckSeconds());
        // Hard limit: if the player never reaches the auth server (or the key never comes) the
        // check still ends with the notice, and the notice itself ends with a kick.
        session.timeoutTask = server.getScheduler()
                .buildTask(plugin, () -> decidePremiumCheck(session))
                .delay(checkSeconds + NOTICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .schedule();
        if (logger.isInfoEnabled()) {
            logger.info(AUTH_MARKER, "[PREMIUM CHECK] Waiting for {} to reach the auth server to verify ownership of premium nick (profile {})",
                    player.getUsername(), premiumUuid);
        }
        return session.done;
    }

    /** True when the Mojang session public key is bundled, i.e. profile keys can be verified. */
    public boolean isPremiumCheckAvailable() {
        return net.rafalohaki.veloauth.premium.MojangProfileKeyVerifier.isAvailable();
    }

    /** True while the player is looking at the premium-name notice (or still being checked). */
    public boolean isPremiumNameNotice(UUID playerId) {
        Session session = playerId == null ? null : sessions.get(playerId);
        return session != null && session.noticeOnly && !session.finished.get();
    }

    /**
     * Re-opens the notice for a player who tried to get around it (chat, {@code /login},
     * {@code /register}, ...). The dialog is the only thing this connection may interact with.
     */
    public void reshowPremiumNameNotice(UUID playerId) {
        Session session = playerId == null ? null : sessions.get(playerId);
        if (session == null || !session.noticeOnly || session.finished.get() || session.premiumCheck != null) {
            return;
        }
        if (session.language == null) {
            session.language = resolveLanguage(session.player);
        }
        transport.show(session.player, premiumNameDialog(session));
    }

    public boolean isPremiumCheck(UUID playerId) {
        Session session = playerId == null ? null : sessions.get(playerId);
        return session != null && session.premiumCheck != null && !session.finished.get();
    }

    /** Called when the player entered PLAY on a server: shows the "checking" dialog and arms the decision. */
    private void onPremiumCheckInPlay(Session session) {
        PremiumCheck check = session.premiumCheck;
        if (check == null || check.inPlay || session.finished.get()) {
            return;
        }
        check.inPlay = true;
        long deadline = System.nanoTime()
                + TimeUnit.MILLISECONDS.toNanos(settings.getDialogSettings().getLocaleWaitMillis());
        resolveLanguageThenShow(session, deadline);
        int checkSeconds = Math.max(1, settings.getDialogSettings().getPremiumCheckSeconds());
        check.decisionTask = server.getScheduler()
                .buildTask(plugin, () -> decidePremiumCheck(session))
                .delay(checkSeconds, TimeUnit.SECONDS)
                .schedule();
    }

    private void onRawPacket(Session session, io.netty.buffer.ByteBuf raw) {
        PremiumCheck check = session.premiumCheck;
        if (check == null || check.keyVerified || session.finished.get()) {
            return;
        }
        net.rafalohaki.veloauth.premium.ProfileKeyPacket packet =
                net.rafalohaki.veloauth.premium.ProfileKeyPacket.tryParse(raw,
                        VelocityDialogTransport.playChatSessionId(session.player.getProtocolVersion().getProtocol()));
        if (packet == null) {
            return;
        }
        boolean valid = net.rafalohaki.veloauth.premium.MojangProfileKeyVerifier.verify(
                check.premiumUuid, packet.expiresAt(), packet.publicKey(), packet.signature(),
                System.currentTimeMillis());
        if (!valid) {
            logger.info(AUTH_MARKER, "[PREMIUM CHECK] {} sent a profile key that is NOT a Mojang certificate for {} - treating as cracked",
                    session.player.getUsername(), check.premiumUuid);
            return;
        }
        check.keyVerified = true;
        logger.info(AUTH_MARKER, "[PREMIUM CHECK] {} presented a valid Mojang profile key for {} - premium owner confirmed",
                session.player.getUsername(), check.premiumUuid);
        runAsync(session, () -> decidePremiumCheck(session));
    }

    private void decidePremiumCheck(Session session) {
        PremiumCheck check = session.premiumCheck;
        if (check == null || session.finished.get() || !check.decided.compareAndSet(false, true)) {
            return;
        }
        if (check.decisionTask != null) {
            check.decisionTask.cancel();
        }
        if (session.timeoutTask != null) {
            session.timeoutTask.cancel();
        }
        Player player = session.player;
        if (!player.isActive()) {
            session.finish();
            return;
        }
        if (session.language == null || !check.inPlay) {
            session.language = resolveLanguage(player);
            rememberLanguage(player, session.language);
        }
        clearPremiumCheckActionBar(player, check);
        if (check.keyVerified) {
            try {
                check.onVerified.run();
            } catch (RuntimeException e) {
                logger.warn(AUTH_MARKER, "Premium hand-over for {} failed: {}", player.getUsername(), e.toString());
                disconnect(session, "connection.premium_name.verified_reconnect");
            }
            session.finish();
            return;
        }
        logger.info(AUTH_MARKER, "[PREMIUM CHECK] No Mojang profile key from {} - cracked client on premium nick, showing notice",
                player.getUsername());
        session.premiumCheck = null; // from here on this is a plain notice session
        session.timeoutTask = server.getScheduler()
                .buildTask(plugin, () -> disconnect(session, PREMIUM_NAME_KICKED_KEY,
                        settings.getDialogSettings().getServerName()))
                .delay(NOTICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .schedule();
        if (!transport.show(player, premiumNameDialog(session))) {
            disconnect(session, PREMIUM_NAME_KICK_KEY, player.getUsername());
        }
    }

    /**
     * The check is silent: only the action bar shows "Checking your account..." in the player's
     * language (re-sent every second because the client fades it out). Nothing is written to chat.
     */
    private void showPremiumCheckActionBar(Session session) {
        PremiumCheck check = session.premiumCheck;
        if (check == null || session.finished.get()) {
            return;
        }
        Component title = text(session.language, "dialog.premium_check.title", NamedTextColor.GOLD);
        check.actionBarTask = server.getScheduler()
                .buildTask(plugin, () -> {
                    if (session.player.isActive() && !check.decided.get()) {
                        session.player.sendActionBar(title);
                    }
                })
                .repeat(ACTION_BAR_REFRESH_MILLIS, TimeUnit.MILLISECONDS)
                .schedule();
    }

    private void clearPremiumCheckActionBar(Player player, PremiumCheck check) {
        ScheduledTask task = check.actionBarTask;
        if (task != null) {
            check.actionBarTask = null;
            task.cancel();
        }
        if (player.isActive()) {
            player.sendActionBar(Component.empty());
        }
    }

    /** Resolves the message language for a player exactly like the dialog flow does. */
    public String languageFor(Player player) {
        return resolveLanguage(player);
    }

    /**
     * Last language resolved for {@code ip|nick}, or {@code null}. Lets pre-login denials (brute
     * force block, etc.) - where the client has not sent its settings yet - reuse the language
     * seen in the player's previous dialog session.
     */
    public String rememberedLanguage(String ip, String nickname) {
        if (ip == null || nickname == null) {
            return null;
        }
        return recentLanguages.getIfPresent(ip + '|' + nickname.toLowerCase(Locale.ROOT));
    }

    private void rememberLanguage(Player player, String language) {
        if (language == null) {
            return;
        }
        recentLanguages.put(net.rafalohaki.veloauth.util.PlayerAddressUtils.getPlayerIp(player)
                + '|' + player.getUsername().toLowerCase(Locale.ROOT), language);
    }

    /** True while the player is inside a dialog session and not yet on any server. */
    public boolean isPreJoinSession(UUID playerId) {
        Session session = playerId == null ? null : sessions.get(playerId);
        return session != null && !session.finished.get() && session.player.getCurrentServer().isEmpty();
    }

    /**
     * Consumes the "authenticated via dialog" mark for the initial server connection. Returns
     * {@code true} exactly once per successful dialog session, and only while the authorization is
     * still valid.
     */
    public boolean consumeAuthenticated(Player player) {
        if (player == null || !authenticatedPreJoin.contains(player.getUniqueId())) {
            return false;
        }
        // The mark stays until the player actually reaches a server (see onServerConnected) so a
        // retried initial connection is still routed to the backend instead of the auth server.
        return bridge.isAuthenticated(player);
    }

    /**
     * Server arrival: premium check / form session continue on the auth server, end elsewhere.
     *
     * @return {@code true} when a dialog-format connection reached a backend server - the chat
     *         filter ends there and the caller must not send the classic chat welcome
     */
    public boolean onServerConnected(Player player, boolean authServer) {
        if (player == null) {
            return false;
        }
        UUID playerId = player.getUniqueId();
        authenticatedPreJoin.remove(playerId);
        boolean backendReached = !authServer && dialogConnections.contains(playerId);
        if (backendReached) {
            // Backend reached: the backend's own chat must arrive again.
            transport.unmuteChat(player);
        }
        Session session = sessions.get(playerId);
        if (session == null || session.finished.get()) {
            return backendReached;
        }
        if (session.premiumCheck != null) {
            onPremiumCheckInPlay(session);
        } else if (authServer) {
            if (!session.noticeOnly) {
                startFormInPlay(session);
            }
        } else if (!session.noticeOnly) {
            transport.clear(session.player);
            session.finish();
        }
        return backendReached;
    }

    /** Clears per-connection state when the player leaves. */
    public void onDisconnect(UUID playerId) {
        authenticatedPreJoin.remove(playerId);
        dialogConnections.remove(playerId);
        Session session = sessions.get(playerId);
        if (session != null) {
            session.finish();
        }
    }

    public void shutdown() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        sessions.values().forEach(Session::finish);
        sessions.clear();
        authenticatedPreJoin.clear();
        dialogConnections.clear();
    }

    public int activeSessions() {
        return sessions.size();
    }

    // ------------------------------------------------------------------ language

    private void resolveLanguageThenShow(Session session, long deadlineNanos) {
        if (session.finished.get()) {
            return;
        }
        Player player = session.player;
        if (!player.isActive()) {
            session.finish();
            return;
        }
        if (hasClientSettings(player) || System.nanoTime() >= deadlineNanos) {
            session.language = resolveLanguage(player);
            rememberLanguage(player, session.language);
            if (logger.isDebugEnabled()) {
                logger.debug(AUTH_MARKER, "Dialog language for {}: client={} -> {}",
                        player.getUsername(), MinecraftLocales.toMinecraftCode(clientLocale(player)), session.language);
            }
            runAsync(session, () -> showInitialForm(session));
            return;
        }
        server.getScheduler()
                .buildTask(plugin, () -> resolveLanguageThenShow(session, deadlineNanos))
                .delay(LOCALE_POLL_MILLIS, TimeUnit.MILLISECONDS)
                .schedule();
    }

    private static boolean hasClientSettings(Player player) {
        try {
            return player.hasSentPlayerSettings();
        } catch (RuntimeException | LinkageError olderApi) {
            return player.getEffectiveLocale() != null;
        }
    }

    private static Locale clientLocale(Player player) {
        try {
            Locale locale = player.getEffectiveLocale();
            if (locale == null && player.getPlayerSettings() != null) {
                locale = player.getPlayerSettings().getLocale();
            }
            return locale;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private String resolveLanguage(Player player) {
        String fallback = messages.getCurrentLanguage();
        if (!settings.isDetectClientLanguage()) {
            return fallback;
        }
        return MinecraftLocales.resolve(clientLocale(player), messages::isLanguageSupported, fallback);
    }

    // ------------------------------------------------------------------ forms

    private void showInitialForm(Session session) {
        if (session.premiumCheck != null) {
            showPremiumCheckActionBar(session);
            return;
        }
        if (session.noticeOnly) {
            if (logger.isInfoEnabled()) {
                logger.info(AUTH_MARKER, "Showing premium-name notice to cracked client {} (language {})",
                        session.player.getUsername(), session.language);
            }
            if (!transport.show(session.player, premiumNameDialog(session))) {
                disconnect(session, PREMIUM_NAME_KICK_KEY, session.player.getUsername());
            }
            return;
        }
        Optional<Boolean> registered = bridge.isRegistered(session.player);
        if (registered.isEmpty()) {
            disconnect(session, "connection.error.database");
            return;
        }
        session.form = registered.get() ? Form.LOGIN : Form.REGISTER;
        showForm(session, session.form);
    }

    private void showForm(Session session, Form form) {
        if (session.finished.get()) {
            return;
        }
        session.form = form;
        session.formShown = true;
        CompoundBinaryTag dialog = switch (form) {
            case LOGIN -> loginDialog(session);
            case REGISTER -> registerDialog(session);
            case TOTP -> totpDialog(session);
        };
        if (!transport.show(session.player, dialog)) {
            // Connection gone - nothing more to do here.
            session.finish();
        }
    }

    private CompoundBinaryTag loginDialog(Session session) {
        String lang = session.language;
        String name = session.player.getUsername();
        int maxLength = Math.max(32, bridge.passwordSettings().maxLength());
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog(session.allowCancel() ? "minecraft:confirmation" : "minecraft:notice",
                        text(lang, "dialog.login.title", NamedTextColor.GOLD))
                .body(DialogNbt.plainMessage(text(lang, "dialog.login.body", NamedTextColor.WHITE, name), BODY_WIDTH))
                .input(DialogNbt.textInput("password",
                        text(lang, "dialog.login.password", NamedTextColor.GRAY), maxLength, INPUT_WIDTH));
        return withButtons(builder, session, "login");
    }

    private CompoundBinaryTag registerDialog(Session session) {
        String lang = session.language;
        String name = session.player.getUsername();
        int maxLength = Math.max(32, bridge.passwordSettings().maxLength());
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog(session.allowCancel() ? "minecraft:confirmation" : "minecraft:notice",
                        text(lang, "dialog.register.title", NamedTextColor.GOLD))
                .body(DialogNbt.plainMessage(text(lang, "dialog.register.body", NamedTextColor.WHITE, name), BODY_WIDTH))
                .input(DialogNbt.textInput("password",
                        text(lang, "dialog.register.password", NamedTextColor.GRAY), maxLength, INPUT_WIDTH))
                .input(DialogNbt.textInput("confirm",
                        text(lang, "dialog.register.confirm", NamedTextColor.GRAY), maxLength, INPUT_WIDTH));
        return withButtons(builder, session, "register");
    }

    private CompoundBinaryTag totpDialog(Session session) {
        String lang = session.language;
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog(session.allowCancel() ? "minecraft:confirmation" : "minecraft:notice",
                        text(lang, "dialog.totp.title", NamedTextColor.GOLD))
                .body(DialogNbt.plainMessage(text(lang, "dialog.totp.body", NamedTextColor.WHITE), BODY_WIDTH))
                .input(DialogNbt.textInput("code",
                        text(lang, "dialog.totp.code", NamedTextColor.GRAY), 12, INPUT_WIDTH));
        return withButtons(builder, session, "totp");
    }

    private CompoundBinaryTag withButtons(DialogNbt.DialogBuilder builder, Session session, String action) {
        String lang = session.language;
        CompoundBinaryTag confirm = DialogNbt.customButton(
                text(lang, "dialog.button.confirm", NamedTextColor.GREEN), action, null, BUTTON_WIDTH);
        if (session.allowCancel()) {
            CompoundBinaryTag exit = DialogNbt.customButton(
                    text(lang, "dialog.button.exit", NamedTextColor.RED), "exit", null, BUTTON_WIDTH);
            builder.confirmation(confirm, exit);
        } else {
            builder.notice(confirm);
        }
        return builder.build();
    }

    private CompoundBinaryTag premiumNameDialog(Session session) {
        String lang = session.language;
        String name = session.player.getUsername();
        Component body = Component.text()
                .append(text(lang, "dialog.premium_name.body", NamedTextColor.WHITE, name))
                .append(Component.newline()).append(Component.newline())
                .append(text(lang, "dialog.premium_name.hint", NamedTextColor.YELLOW))
                .build();
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog("minecraft:notice", text(lang, "dialog.premium_name.title", NamedTextColor.RED))
                .afterAction("close")
                .closableWithEscape(false);
        if (settings.getDialogSettings().isErrorIcon()) {
            builder.body(DialogNbt.itemMessage("minecraft:name_tag", body, BODY_WIDTH));
        } else {
            builder.body(DialogNbt.plainMessage(body, BODY_WIDTH));
        }
        builder.notice(DialogNbt.customButton(text(lang, "dialog.premium_name.button", NamedTextColor.GREEN),
                "premium_name_ack", null, NOTICE_BUTTON_WIDTH));
        return builder.build();
    }

    private CompoundBinaryTag errorDialog(Session session, Component message, Form returnTo) {
        String lang = session.language;
        CompoundBinaryTag additions = CompoundBinaryTag.builder()
                .putString("form", returnTo.name().toLowerCase(Locale.ROOT))
                .build();
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog("minecraft:notice", text(lang, "dialog.error.title", NamedTextColor.RED));
        if (settings.getDialogSettings().isErrorIcon()) {
            builder.body(DialogNbt.itemMessage("minecraft:barrier", message, BODY_WIDTH));
        } else {
            builder.body(DialogNbt.plainMessage(message, BODY_WIDTH));
        }
        builder.notice(DialogNbt.customButton(
                text(lang, "dialog.button.back", NamedTextColor.YELLOW), "back", additions, BUTTON_WIDTH));
        return builder.build();
    }

    private Component text(String language, String key, NamedTextColor color, Object... args) {
        return messages.componentForLanguage(language, key, color, args);
    }

    // ------------------------------------------------------------------ clicks

    private void onClick(Session session, DialogClick click) {
        if (session.finished.get()) {
            return;
        }
        // Clicks are processed strictly in order on a per-session chain. A dialog response is
        // sent *inside* the previous step, so a fast client may answer before that step has
        // fully returned - queueing (instead of dropping) keeps such clicks.
        if (session.pending.incrementAndGet() > MAX_PENDING_CLICKS) {
            session.pending.decrementAndGet();
            if (logger.isDebugEnabled()) {
                logger.debug(AUTH_MARKER, "Ignoring dialog click '{}' from {} - too many queued actions",
                        click.action(), session.player.getUsername());
            }
            return;
        }
        session.chainLock.lock();
        try {
            session.chain = session.chain.handle((ignored, throwable) -> null).thenRunAsync(() -> {
                try {
                    if (!session.finished.get()) {
                        handleClick(session, click);
                    }
                } finally {
                    session.pending.decrementAndGet();
                }
            }, VirtualThreadExecutorProvider.getVirtualExecutor()).exceptionally(throwable -> {
                logger.error(AUTH_MARKER, "Dialog authentication step failed for {}",
                        session.player.getUsername(), throwable);
                disconnect(session, "connection.error.generic");
                return null;
            });
        } finally {
            session.chainLock.unlock();
        }
    }

    private void handleClick(Session session, DialogClick click) {
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Dialog click '{}' from {} (form {})", click.action(),
                    session.player.getUsername(), session.form);
        }
        if (session.premiumCheck != null) {
            return; // still checking - the dialog has no actionable button
        }
        if (session.noticeOnly) {
            handleNoticeClick(session, click);
            return;
        }
        switch (click.action()) {
            case "login" -> handleLoginClick(session, click);
            case "register" -> handleRegisterClick(session, click);
            case "totp" -> handleTotpClick(session, click);
            case "back" -> handleBackClick(session, click);
            case "exit" -> disconnect(session, "dialog.cancelled");
            default -> showForm(session, session.form);
        }
    }

    private void handleNoticeClick(Session session, DialogClick click) {
        // Single "Got it" button: the client closes the dialog itself (after_action=close) and the
        // proxy disconnects the connection right away. Nothing is authenticated.
        if (logger.isInfoEnabled()) {
            logger.info(AUTH_MARKER, "{} acknowledged premium-name notice ({}) - disconnecting",
                    session.player.getUsername(), click.action());
        }
        disconnect(session, PREMIUM_NAME_KICKED_KEY, settings.getDialogSettings().getServerName());
    }

    private void handleLoginClick(Session session, DialogClick click) {
        String password = click.text("password");
        if (password == null || password.isEmpty()) {
            showError(session, text(session.language, "dialog.error.empty_password", NamedTextColor.RED), Form.LOGIN);
            return;
        }
        handleResult(session, bridge.login(session.player, password), Form.LOGIN);
    }

    private void handleRegisterClick(Session session, DialogClick click) {
        String password = click.text("password");
        String confirm = click.text("confirm");
        if (password == null || password.isEmpty()) {
            showError(session, text(session.language, "dialog.error.empty_password", NamedTextColor.RED), Form.REGISTER);
            return;
        }
        handleResult(session, bridge.register(session.player, password, confirm == null ? "" : confirm), Form.REGISTER);
    }

    private void handleTotpClick(Session session, DialogClick click) {
        String code = click.text("code");
        if (code == null || code.isBlank()) {
            showError(session, text(session.language, "dialog.error.empty_code", NamedTextColor.RED), Form.TOTP);
            return;
        }
        handleResult(session, bridge.verifyTotp(session.player, code), Form.TOTP);
    }

    private void handleBackClick(Session session, DialogClick click) {
        Player player = session.player;
        Form form = parseForm(click.text("form"), session.form);
        if (form == Form.TOTP && !bridge.isTotpPending(player)) {
            form = Form.LOGIN;
        }
        if (form != Form.TOTP) {
            // Re-check the account state so "back" always lands on the right form,
            // e.g. after a /login attempt on an account that is not registered yet.
            form = bridge.isRegistered(player).map(r -> r ? Form.LOGIN : Form.REGISTER).orElse(form);
        }
        showForm(session, form);
    }

    private static Form parseForm(String raw, Form fallback) {
        if (raw == null) {
            return fallback;
        }
        try {
            return Form.valueOf(raw.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            return fallback;
        }
    }

    private void handleResult(Session session, DialogAuthBridge.Result result, Form form) {
        Player player = session.player;
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Dialog {} result for {}: {} ({})", form, player.getUsername(),
                    result.outcome(), result.messageKey());
        }
        switch (result.outcome()) {
            case SUCCESS -> {
                authenticatedPreJoin.add(player.getUniqueId());
                transport.clear(player);
                if (logger.isInfoEnabled()) {
                    logger.info(AUTH_MARKER, "Player {} authenticated via dialog ({}, language {})",
                            player.getUsername(), form.name().toLowerCase(Locale.ROOT), session.language);
                }
                session.finish();
                scheduleForwardCheck(player, 1);
            }
            case TOTP_REQUIRED -> showForm(session, Form.TOTP);
            case FAILED -> {
                if (!player.isActive()) {
                    session.finish();
                    return;
                }
                if (BRUTE_FORCE_BLOCKED_KEY.equals(result.messageKey())) {
                    // Same outcome as VeloAuth's own pre-login block: the connection is refused
                    // with the localized "too many attempts" message instead of looping the form.
                    logger.warn(AUTH_MARKER, "Disconnecting {} from dialog login - brute-force block reached",
                            player.getUsername());
                    disconnect(session, BRUTE_FORCE_BLOCKED_KEY);
                    return;
                }
                Component message = bridge.render(result, session.language, NamedTextColor.RED);
                Form returnTo = form == Form.TOTP && !bridge.isTotpPending(player) ? Form.LOGIN : form;
                showError(session, message, returnTo);
            }
        }
    }

    // ------------------------------------------------------------------ forwarding safety net

    private static final int[] FORWARD_CHECK_DELAYS_SECONDS = {3, 8, 15};

    /**
     * Velocity resumes the suspended PostLoginEvent and picks the initial server itself. As a
     * safety net we verify a few seconds later that the player really left the configuration
     * phase: if they are still on no server we connect them to a backend explicitly, and if they
     * somehow landed on the auth server we hand them to VeloAuth's regular auto-transfer.
     */
    private void scheduleForwardCheck(Player player, int attempt) {
        if (attempt > FORWARD_CHECK_DELAYS_SECONDS.length) {
            return;
        }
        server.getScheduler()
                .buildTask(plugin, () -> ensureForwarded(player, attempt))
                .delay(FORWARD_CHECK_DELAYS_SECONDS[attempt - 1], TimeUnit.SECONDS)
                .schedule();
    }

    private void ensureForwarded(Player player, int attempt) {
        if (closed.get() || !player.isActive() || !bridge.isAuthenticated(player)) {
            return;
        }
        net.rafalohaki.veloauth.connection.ConnectionManager connections = plugin.getConnectionManager();
        if (connections == null) {
            return;
        }
        Optional<com.velocitypowered.api.proxy.ServerConnection> current = player.getCurrentServer();
        if (current.isPresent()) {
            if (connections.isAuthServer(current.get().getServer())) {
                logger.info(AUTH_MARKER, "Dialog-authenticated player {} is on the auth server - auto-transferring to backend",
                        player.getUsername());
                connections.autoTransferFromAuthServerToBackend(player);
            }
            return;
        }
        connections.findAvailableBackendServerForInitialConnectionAsync().thenAccept(backend -> {
            if (!player.isActive() || player.getCurrentServer().isPresent() || !bridge.isAuthenticated(player)) {
                return;
            }
            if (backend.isEmpty()) {
                logger.warn(AUTH_MARKER, "Player {} is still not on any server {}s after dialog login and no backend is available",
                        player.getUsername(), FORWARD_CHECK_DELAYS_SECONDS[attempt - 1]);
                scheduleForwardCheck(player, attempt + 1);
                return;
            }
            logger.warn(AUTH_MARKER, "Player {} is still not on any server {}s after dialog login - connecting to {} explicitly",
                    player.getUsername(), FORWARD_CHECK_DELAYS_SECONDS[attempt - 1],
                    backend.get().getServerInfo().getName());
            player.createConnectionRequest(backend.get()).connect().whenComplete((result, throwable) -> {
                if (throwable != null || result == null || !result.isSuccessful()) {
                    scheduleForwardCheck(player, attempt + 1);
                }
            });
        });
    }

    private void showError(Session session, Component message, Form returnTo) {
        if (session.finished.get()) {
            return;
        }
        if (!transport.show(session.player, errorDialog(session, message, returnTo))) {
            session.finish();
        }
    }

    // ------------------------------------------------------------------ termination

    private void onTimeout(Session session) {
        if (session.finished.get()) {
            return;
        }
        if (logger.isInfoEnabled()) {
            logger.info(AUTH_MARKER, "Player {} did not finish dialog authentication within {}s - disconnecting",
                    session.player.getUsername(), settings.getDialogSettings().getTimeoutSeconds());
        }
        disconnect(session, "dialog.timeout", settings.getDialogSettings().getTimeoutSeconds());
    }

    private void disconnect(Session session, String key, Object... args) {
        disconnect(session, text(session.language, key, NamedTextColor.RED, args));
    }

    private void disconnect(Session session, Component reason) {
        if (session.finished.get()) {
            return;
        }
        try {
            session.player.disconnect(reason);
        } catch (RuntimeException e) {
            logger.debug("Failed to disconnect {} from dialog: {}", session.player.getUsername(), e.toString());
        } finally {
            session.finish();
        }
    }

    private boolean runAsync(Session session, Runnable task) {
        try {
            CompletableFuture.runAsync(task, VirtualThreadExecutorProvider.getVirtualExecutor())
                    .exceptionally(throwable -> {
                        logger.error(AUTH_MARKER, "Dialog authentication step failed for {}",
                                session.player.getUsername(), throwable);
                        disconnect(session, "connection.error.generic");
                        return null;
                    });
            return true;
        } catch (RejectedExecutionException shuttingDown) {
            session.finish();
            return false;
        }
    }

    // ------------------------------------------------------------------ session

    /** State of a premium-nick ownership check running on the auth server. */
    private static final class PremiumCheck {
        private final UUID premiumUuid;
        private final Runnable onVerified;
        private final AtomicBoolean decided = new AtomicBoolean();
        private volatile boolean keyVerified;
        private volatile boolean inPlay;
        private volatile ScheduledTask decisionTask;
        private volatile ScheduledTask actionBarTask;

        private PremiumCheck(UUID premiumUuid, Runnable onVerified) {
            this.premiumUuid = premiumUuid;
            this.onVerified = onVerified;
        }
    }

    private final class Session {
        private final Player player;
        private final CompletableFuture<Void> done = new CompletableFuture<>();
        private final AtomicBoolean finished = new AtomicBoolean();
        private final java.util.concurrent.atomic.AtomicInteger pending = new java.util.concurrent.atomic.AtomicInteger();
        private final java.util.concurrent.locks.ReentrantLock chainLock = new java.util.concurrent.locks.ReentrantLock();
        private CompletableFuture<Void> chain = CompletableFuture.completedFuture(null);
        private volatile String language;
        private volatile Form form = Form.LOGIN;
        private volatile boolean formShown;
        private volatile boolean noticeOnly;
        /** Premium ownership check (limbo + profile-key verification); null for other sessions. */
        private volatile PremiumCheck premiumCheck;
        private volatile ScheduledTask keepAliveTask;
        private volatile ScheduledTask timeoutTask;

        private Session(Player player) {
            this.player = player;
            this.language = messages.getCurrentLanguage();
        }

        private boolean allowCancel() {
            return settings.getDialogSettings().isAllowCancel();
        }

        private void finish() {
            if (!finished.compareAndSet(false, true)) {
                return;
            }
            ScheduledTask keepAlive = keepAliveTask;
            if (keepAlive != null) {
                keepAlive.cancel();
            }
            ScheduledTask timeout = timeoutTask;
            if (timeout != null) {
                timeout.cancel();
            }
            PremiumCheck check = premiumCheck;
            if (check != null) {
                if (check.decisionTask != null) {
                    check.decisionTask.cancel();
                }
                ScheduledTask bar = check.actionBarTask;
                if (bar != null) {
                    bar.cancel();
                }
            }
            transport.detachClickListener(player);
            sessions.remove(player.getUniqueId(), this);
            done.complete(null);
        }
    }
}
