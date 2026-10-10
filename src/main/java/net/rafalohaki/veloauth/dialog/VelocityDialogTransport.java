package net.rafalohaki.veloauth.dialog;

import com.velocitypowered.api.proxy.Player;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufHolder;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.util.ReferenceCountUtil;
import net.kyori.adventure.nbt.BinaryTag;
import net.kyori.adventure.nbt.BinaryTagIO;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import org.slf4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.function.Consumer;

/**
 * Sends dialogs to, and receives dialog clicks from, a client that is still in the
 * CONFIGURATION phase (i.e. before Velocity has connected it to any backend).
 *
 * <p>Velocity's public API declares {@code Player#showDialog} but does not implement it, so this
 * class talks to a handful of well-known proxy internals (identical on Velocity 3.4.x, 3.5.x and
 * 4.x). All internal access is resolved once, through method handles, and any failure disables
 * the dialog feature with a clear log line instead of breaking authentication; the classic
 * auth-server + {@code /login} flow is always available as fallback.
 *
 * <p>Protocol facts (1.21.6 / protocol 771 up to 26.3 / protocol 777):
 * <ul>
 *   <li>clientbound {@code show_dialog} in CONFIGURATION carries the dialog NBT directly
 *       (no registry holder), id {@code 0x12} (771-776) / {@code 0x13} (777);</li>
 *   <li>clientbound {@code clear_dialog} id {@code 0x11} (771-776) / {@code 0x12} (777);</li>
 *   <li>serverbound {@code custom_click_action} id {@code 0x08}: identifier + length-prefixed
 *       optional NBT payload.</li>
 * </ul>
 * Velocity registers these packets itself; VeloAuth prefers Velocity's own packet classes so new
 * protocol ids are picked up automatically and only falls back to the table above when needed.
 */
public final class VelocityDialogTransport {

    /** First protocol version that understands dialogs (Minecraft 1.21.6). */
    public static final int MIN_DIALOG_PROTOCOL = 771;
    /** Minecraft 26.3. */
    public static final int PROTOCOL_26_3 = 777;
    /** Minecraft 26.1 (26.2 = 776 shares its ids). */
    public static final int PROTOCOL_26_1 = 775;
    /** Minecraft 1.21.9 (1.21.11 = 774 shares its ids). */
    public static final int PROTOCOL_1_21_9 = 773;

    private static final String HANDLER_NAME = "veloauth-dialog-click";
    private static final String MINECRAFT_DECODER = "minecraft-decoder";
    private static final String MINECRAFT_ENCODER = "minecraft-encoder";
    private static final String JOIN_GAME_HANDLER_NAME = "veloauth-joingame-online";
    private static final String CHAT_MUTE_HANDLER_NAME = "veloauth-chat-mute";
    private static final String CLS_SYSTEM_CHAT = "com.velocitypowered.proxy.protocol.packet.chat.SystemChatPacket";
    private static final String CLS_JOIN_GAME = "com.velocitypowered.proxy.protocol.packet.JoinGamePacket";
    private static final String CLS_CONNECTED_PLAYER = "com.velocitypowered.proxy.connection.client.ConnectedPlayer";
    private static final String CLS_MINECRAFT_CONNECTION = "com.velocitypowered.proxy.connection.MinecraftConnection";
    private static final String CLS_STATE_REGISTRY = "com.velocitypowered.proxy.protocol.StateRegistry";
    private static final String CLS_DIALOG_SHOW = "com.velocitypowered.proxy.protocol.packet.DialogShowPacket";
    private static final String CLS_DIALOG_CLEAR = "com.velocitypowered.proxy.protocol.packet.DialogClearPacket";
    private static final String CLS_CUSTOM_CLICK = "com.velocitypowered.proxy.protocol.packet.ServerboundCustomClickActionPacket";
    private static final int MAX_CLICK_PAYLOAD = 65_536;
    /** NBT tag id of TAG_Compound; kept as a literal to avoid BinaryTagType method calls (see writeNbt). */
    private static final byte NBT_TYPE_COMPOUND = 10;

    private final Logger logger;
    private final boolean available;
    private final String unavailableReason;

    // Resolved internals (null when unavailable)
    private final Class<?> connectedPlayerClass;
    private final MethodHandle getConnection;
    private final MethodHandle sendKeepAlive;
    private final MethodHandle connectionWrite;
    private final MethodHandle connectionGetChannel;
    private final MethodHandle connectionGetState;
    private final MethodHandle connectionIsClosed;
    private final Object stateConfig;
    private final Object statePlay;
    private final MethodHandle dialogShowCtor;      // (StateRegistry) -> DialogShowPacket, may be null
    private final Field dialogShowNbtField;         // may be null
    private final Field dialogShowIdField;          // may be null
    private final Object dialogClearInstance;       // may be null
    private final Class<?> customClickClass;

    public VelocityDialogTransport(Logger logger) {
        this.logger = logger;
        Internals resolved = null;
        String reason = null;
        try {
            resolved = resolveInternals(logger);
        } catch (ReflectiveOperationException | RuntimeException e) {
            reason = e.toString();
        }
        Internals safe = resolved == null ? Internals.NONE : resolved;
        this.connectedPlayerClass = safe.connectedPlayerClass();
        this.getConnection = safe.getConnection();
        this.sendKeepAlive = safe.sendKeepAlive();
        this.connectionWrite = safe.connectionWrite();
        this.connectionGetChannel = safe.connectionGetChannel();
        this.connectionGetState = safe.connectionGetState();
        this.connectionIsClosed = safe.connectionIsClosed();
        this.stateConfig = safe.stateConfig();
        this.statePlay = safe.statePlay();
        this.customClickClass = safe.customClickClass();
        this.dialogShowCtor = safe.packets().showCtor();
        this.dialogShowNbtField = safe.packets().nbtField();
        this.dialogShowIdField = safe.packets().idField();
        this.dialogClearInstance = safe.packets().clearInstance();
        this.available = resolved != null;
        this.unavailableReason = reason;
        if (available) {
            logger.info("Dialog transport ready (velocity internals: {}, encoder: {})",
                    "ok", dialogShowCtor != null ? "velocity-packets" : "raw");
        } else {
            logger.warn("Dialog transport unavailable - GUI login disabled, classic /login flow stays active: {}", reason);
        }
    }

    /** Resolved Velocity internals; all members non-null except in {@link #NONE}. */
    private record Internals(Class<?> connectedPlayerClass, MethodHandle getConnection, MethodHandle sendKeepAlive,
                             MethodHandle connectionWrite, MethodHandle connectionGetChannel,
                             MethodHandle connectionGetState, MethodHandle connectionIsClosed, Object stateConfig,
                             Object statePlay, Class<?> customClickClass, DialogPackets packets) {
        static final Internals NONE = new Internals(null, null, null, null, null, null, null, null, null, null,
                DialogPackets.NONE);
    }

    /** Velocity's own dialog packet classes (preferred encoder); {@link #NONE} when absent. */
    private record DialogPackets(MethodHandle showCtor, Field nbtField, Field idField, Object clearInstance) {
        static final DialogPackets NONE = new DialogPackets(null, null, null, null);
    }

    private static Internals resolveInternals(Logger logger) throws ReflectiveOperationException {
        ClassLoader loader = Player.class.getClassLoader();
        MethodHandles.Lookup lookup = MethodHandles.publicLookup();
        Class<?> cpClass = Class.forName(CLS_CONNECTED_PLAYER, false, loader);
        Class<?> mcClass = Class.forName(CLS_MINECRAFT_CONNECTION, false, loader);
        Class<?> stateClass = Class.forName(CLS_STATE_REGISTRY, false, loader);
        Class<?> clickClass = Class.forName(CLS_CUSTOM_CLICK, false, loader);
        Object config = null;
        Object play = null;
        for (Object constant : stateClass.getEnumConstants()) {
            String name = ((Enum<?>) constant).name();
            if ("CONFIG".equals(name)) {
                config = constant;
            } else if ("PLAY".equals(name)) {
                play = constant;
            }
        }
        if (config == null || play == null) {
            throw new IllegalStateException("StateRegistry.CONFIG/PLAY not found");
        }
        return new Internals(
                cpClass,
                lookup.findVirtual(cpClass, "getConnection", MethodType.methodType(mcClass)),
                lookup.findVirtual(cpClass, "sendKeepAlive", MethodType.methodType(void.class)),
                lookup.findVirtual(mcClass, "write", MethodType.methodType(io.netty.channel.ChannelFuture.class, Object.class)),
                lookup.findVirtual(mcClass, "getChannel", MethodType.methodType(Channel.class)),
                lookup.findVirtual(mcClass, "getState", MethodType.methodType(stateClass)),
                lookup.findVirtual(mcClass, "isClosed", MethodType.methodType(boolean.class)),
                config,
                play,
                clickClass,
                resolveDialogPackets(logger, loader, lookup, stateClass));
    }

    // DialogShowPacket keeps its id/nbt behind package-private setters-less fields; writing them
    // reflectively is the only way to reuse Velocity's own encoder (which is the most robust
    // option across protocol versions). Falls back to raw encoding when inaccessible.
    @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
    private static DialogPackets resolveDialogPackets(Logger logger, ClassLoader loader,
                                                      MethodHandles.Lookup lookup, Class<?> stateClass) {
        try {
            Class<?> showClass = Class.forName(CLS_DIALOG_SHOW, false, loader);
            MethodHandle showCtor = lookup.findConstructor(showClass, MethodType.methodType(void.class, stateClass));
            Field nbtField = showClass.getDeclaredField("nbt");
            nbtField.setAccessible(true);
            Field idField = showClass.getDeclaredField("id");
            idField.setAccessible(true);
            Class<?> clearClass = Class.forName(CLS_DIALOG_CLEAR, false, loader);
            Object clearInstance = clearClass.getField("INSTANCE").get(null);
            return new DialogPackets(showCtor, nbtField, idField, clearInstance);
        } catch (ReflectiveOperationException | RuntimeException optional) {
            logger.debug("Velocity dialog packet classes unavailable, using raw packet encoding: {}",
                    optional.toString());
            return DialogPackets.NONE;
        }
    }

    /**
     * Rewrites the {@code onlineMode} flag of the clientbound Login (play) packet to {@code true}
     * for this connection. Since 26.2 the client prepares and sends its Mojang profile key only
     * when that flag is set; Velocity copies it from the connection, which is offline during the
     * premium ownership check. Older Velocity builds without the flag are a no-op.
     *
     * @return {@code true} when the rewriter is installed
     */
    public boolean forceOnlineModeInJoinGame(Player player) {
        try {
            ClassLoader loader = Player.class.getClassLoader();
            Class<?> joinGameClass = Class.forName(CLS_JOIN_GAME, false, loader);
            java.lang.reflect.Method setter;
            try {
                setter = joinGameClass.getMethod("setOnlineMode", boolean.class);
            } catch (NoSuchMethodException older) {
                return false;
            }
            Object connection = getConnection.invoke(player);
            if (connection == null || (boolean) connectionIsClosed.invoke(connection)) {
                return false;
            }
            Channel channel = (Channel) connectionGetChannel.invoke(connection);
            ChannelPipeline pipeline = channel.pipeline();
            if (pipeline.get(JOIN_GAME_HANDLER_NAME) != null) {
                return true;
            }
            ChannelOutboundHandlerAdapter rewriter = new ChannelOutboundHandlerAdapter() {
                @Override
                public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
                    if (joinGameClass.isInstance(msg)) {
                        try {
                            setter.invoke(msg, true);
                        } catch (ReflectiveOperationException | RuntimeException e) {
                            logger.debug("JoinGame onlineMode rewrite failed: {}", e.toString());
                        }
                    }
                    super.write(ctx, msg, promise);
                }
            };
            if (pipeline.get(MINECRAFT_ENCODER) != null) {
                pipeline.addAfter(MINECRAFT_ENCODER, JOIN_GAME_HANDLER_NAME, rewriter);
            } else {
                pipeline.addLast(JOIN_GAME_HANDLER_NAME, rewriter);
            }
            return true;
        } catch (Throwable t) {
            logger.debug("Cannot install JoinGame rewriter for {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /**
     * Stops plain chat lines (clientbound {@code system_chat} without the action-bar overlay) from
     * reaching this player while a dialog session is on screen: the GUI replaces every chat
     * instruction, and neither VeloAuth's nor the auth server's chat spam should appear behind
     * the form. Action bars, titles and dialogs are unaffected. Idempotent.
     */
    public boolean muteChat(Player player) {
        try {
            ClassLoader loader = connectedPlayerClass.getClassLoader();
            Class<?> systemChatClass = Class.forName(CLS_SYSTEM_CHAT, false, loader);
            java.lang.reflect.Method getType = systemChatClass.getMethod("getType");
            Object connection = getConnection.invoke(player);
            if (connection == null || (boolean) connectionIsClosed.invoke(connection)) {
                return false;
            }
            Channel channel = (Channel) connectionGetChannel.invoke(connection);
            ChannelPipeline pipeline = channel.pipeline();
            if (pipeline.get(CHAT_MUTE_HANDLER_NAME) != null) {
                return true;
            }
            ChannelOutboundHandlerAdapter mute = new ChannelOutboundHandlerAdapter() {
                @Override
                public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
                    if (systemChatClass.isInstance(msg) && isPlainChat(msg)) {
                        promise.trySuccess();
                        return;
                    }
                    super.write(ctx, msg, promise);
                }

                private boolean isPlainChat(Object packet) {
                    try {
                        Object type = getType.invoke(packet);
                        return type == null || !"GAME_INFO".equals(String.valueOf(type));
                    } catch (ReflectiveOperationException | RuntimeException e) {
                        return false;
                    }
                }
            };
            if (pipeline.get(MINECRAFT_ENCODER) != null) {
                pipeline.addAfter(MINECRAFT_ENCODER, CHAT_MUTE_HANDLER_NAME, mute);
            } else {
                pipeline.addLast(CHAT_MUTE_HANDLER_NAME, mute);
            }
            return true;
        } catch (Throwable t) {
            logger.debug("Cannot mute chat for {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /** Removes the chat filter installed by {@link #muteChat}. */
    public void unmuteChat(Player player) {
        try {
            Object connection = getConnection.invoke(player);
            if (connection == null) {
                return;
            }
            Channel channel = (Channel) connectionGetChannel.invoke(connection);
            ChannelPipeline pipeline = channel.pipeline();
            if (pipeline.get(CHAT_MUTE_HANDLER_NAME) != null) {
                pipeline.remove(CHAT_MUTE_HANDLER_NAME);
            }
        } catch (Throwable t) {
            logger.debug("Cannot unmute chat for {}: {}", player.getUsername(), t.toString());
        }
    }

    /** Whether the proxy internals needed for dialogs were found. */
    public boolean isAvailable() {
        return available;
    }

    public String unavailableReason() {
        return unavailableReason;
    }

    /** Whether this connection can receive dialogs right now (supported client, CONFIG or PLAY phase). */
    public boolean supports(Player player) {
        if (!available || player == null || !connectedPlayerClass.isInstance(player)) {
            return false;
        }
        if (player.getProtocolVersion().getProtocol() < MIN_DIALOG_PROTOCOL) {
            return false;
        }
        try {
            Object connection = getConnection.invoke(player);
            if (connection == null || (boolean) connectionIsClosed.invoke(connection)) {
                return false;
            }
            return dialogState(connectionGetState.invoke(connection)) != null;
        } catch (Throwable t) {
            logger.debug("Cannot inspect connection state of {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /**
     * Returns the state constant when dialogs can be sent in it. CONFIG uses Velocity's own
     * packet classes; PLAY uses raw frames because Velocity registers {@code DialogShowPacket} /
     * {@code DialogClearPacket} for CONFIG only (writing them in PLAY fails silently).
     */
    private Object dialogState(Object state) {
        if (stateConfig.equals(state)) {
            return stateConfig;
        }
        if (statePlay.equals(state)) {
            return statePlay;
        }
        return null;
    }

    /** Whether the raw PLAY dialog frames are known for this protocol. */
    static boolean supportsPlayDialogs(int protocol) {
        return protocol >= MIN_DIALOG_PROTOCOL && protocol <= PROTOCOL_26_3;
    }

    /** Sends (or replaces) the dialog currently displayed by the client. */
    public boolean show(Player player, CompoundBinaryTag dialog) {
        try {
            Object connection = getConnection.invoke(player);
            if (connection == null || (boolean) connectionIsClosed.invoke(connection)) {
                return false;
            }
            Object state = dialogState(connectionGetState.invoke(connection));
            if (state == null) {
                return false;
            }
            int protocol = player.getProtocolVersion().getProtocol();
            Object packet;
            if (statePlay.equals(state)) {
                if (!supportsPlayDialogs(protocol)) {
                    return false;
                }
                packet = rawPlayShowPacket(protocol, dialog);
            } else {
                packet = buildShowPacket(player, dialog, state);
            }
            connectionWrite.invoke(connection, packet);
            return true;
        } catch (Throwable t) {
            logger.warn("Failed to send dialog to {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /** Closes whatever dialog the client is showing. */
    public boolean clear(Player player) {
        try {
            Object connection = getConnection.invoke(player);
            if (connection == null || (boolean) connectionIsClosed.invoke(connection)) {
                return false;
            }
            Object state = dialogState(connectionGetState.invoke(connection));
            if (state == null) {
                return false;
            }
            int protocol = player.getProtocolVersion().getProtocol();
            Object packet;
            if (statePlay.equals(state)) {
                if (!supportsPlayDialogs(protocol)) {
                    return false;
                }
                packet = rawPacket(playClearDialogId(protocol), null);
            } else {
                packet = dialogClearInstance != null
                        ? dialogClearInstance
                        : rawPacket(clearDialogId(protocol), null);
            }
            connectionWrite.invoke(connection, packet);
            return true;
        } catch (Throwable t) {
            logger.debug("Failed to clear dialog for {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /** Sends a keep-alive so neither side's read timeout fires while the player types. */
    public void keepAlive(Player player) {
        try {
            sendKeepAlive.invoke(player);
        } catch (Throwable t) {
            logger.debug("Keep-alive to {} failed: {}", player.getUsername(), t.toString());
        }
    }

    /**
     * Installs a pipeline handler that consumes {@code veloauth:*} custom click actions for this
     * connection and forwards everything else untouched. Idempotent per connection.
     *
     * @return {@code true} when the handler is (now) installed
     */
    public boolean attachClickListener(Player player, Consumer<DialogClick> listener) {
        return attachClickListener(player, listener, null);
    }

    /**
     * Like {@link #attachClickListener(Player, Consumer)} but additionally lets {@code rawListener}
     * inspect (never consume) every serverbound packet Velocity does not decode itself, e.g. the
     * {@code chat_session_update} profile-key packet.
     */
    public boolean attachClickListener(Player player, Consumer<DialogClick> listener,
                                       Consumer<ByteBuf> rawListener) {
        try {
            Object connection = getConnection.invoke(player);
            if (connection == null) {
                return false;
            }
            Channel channel = (Channel) connectionGetChannel.invoke(connection);
            ChannelPipeline pipeline = channel.pipeline();
            if (pipeline.get(HANDLER_NAME) != null) {
                return true;
            }
            ClickInterceptor interceptor = new ClickInterceptor(listener, rawListener, connection,
                    player.getProtocolVersion().getProtocol());
            if (pipeline.get(MINECRAFT_DECODER) != null) {
                pipeline.addAfter(MINECRAFT_DECODER, HANDLER_NAME, interceptor);
            } else {
                pipeline.addLast(HANDLER_NAME, interceptor);
            }
            return true;
        } catch (Throwable t) {
            logger.warn("Failed to attach dialog click listener for {}: {}", player.getUsername(), t.toString());
            return false;
        }
    }

    /** Removes the click handler installed by {@link #attachClickListener}. */
    public void detachClickListener(Player player) {
        try {
            Object connection = getConnection.invoke(player);
            if (connection == null) {
                return;
            }
            Channel channel = (Channel) connectionGetChannel.invoke(connection);
            ChannelPipeline pipeline = channel.pipeline();
            if (pipeline.get(HANDLER_NAME) != null) {
                pipeline.remove(HANDLER_NAME);
            }
        } catch (Throwable t) {
            logger.debug("Failed to detach dialog click listener for {}: {}", player.getUsername(), t.toString());
        }
    }

    // ------------------------------------------------------------------ encoding helpers

    private Object buildShowPacket(Player player, CompoundBinaryTag dialog, Object state) throws Throwable {
        if (dialogShowCtor != null) {
            Object packet = dialogShowCtor.invoke(state);
            dialogShowIdField.setInt(packet, 0);
            dialogShowNbtField.set(packet, dialog);
            return packet;
        }
        return rawPacket(showDialogId(player.getProtocolVersion().getProtocol()), dialog);
    }

    // PLAY ids per protocol, taken from Mojang's packet reports (1.21.6=771 ... 26.3=777; 26.2 shares
    // the 26.1 ids). Velocity does not register these packets in PLAY, so they are written raw.

    /** Clientbound PLAY {@code show_dialog} id; body is {@code VarInt 0 (inline) + NBT}. */
    static int playShowDialogId(int protocol) {
        if (protocol >= PROTOCOL_26_3) {
            return 0x8F;
        }
        if (protocol >= PROTOCOL_26_1) {
            return 0x8C;
        }
        if (protocol >= PROTOCOL_1_21_9) {
            return 0x8A;
        }
        return 0x85;
    }

    /** Clientbound PLAY {@code clear_dialog} id. */
    static int playClearDialogId(int protocol) {
        return playShowDialogId(protocol) - 1;
    }

    /** Serverbound PLAY {@code custom_click_action} id. */
    static int playCustomClickId(int protocol) {
        return protocol >= PROTOCOL_26_1 ? 0x44 : 0x41;
    }

    /** Serverbound PLAY {@code chat_session_update} (profile key) id. */
    public static int playChatSessionId(int protocol) {
        return protocol >= PROTOCOL_26_1 ? 0x0A : 0x09;
    }

    static ByteBuf rawPlayShowPacket(int protocol, BinaryTag nbt) throws IOException {
        ByteBuf buf = Unpooled.buffer();
        writeVarInt(buf, playShowDialogId(protocol));
        writeVarInt(buf, 0); // inline dialog (not a registry id)
        writeNbt(buf, nbt);
        return buf;
    }

    /** Clientbound CONFIGURATION {@code show_dialog} id (the NBT follows directly, no holder). */
    static int showDialogId(int protocol) {
        return protocol >= PROTOCOL_26_3 ? 0x13 : 0x12;
    }

    /** Clientbound CONFIGURATION {@code clear_dialog} id. */
    static int clearDialogId(int protocol) {
        return protocol >= PROTOCOL_26_3 ? 0x12 : 0x11;
    }

    /** Builds a raw framed packet body: varint id + optional network NBT (nameless root). */
    static ByteBuf rawPacket(int packetId, BinaryTag nbt) throws IOException {
        ByteBuf buf = Unpooled.buffer();
        writeVarInt(buf, packetId);
        if (nbt != null) {
            writeNbt(buf, nbt);
        }
        return buf;
    }

    /**
     * Writes a network ("nameless") compound tag. Deliberately avoids invoking methods on
     * {@code BinaryTagType}: it is an abstract class in Adventure 4.x (Velocity 3.x) but an
     * interface in Adventure 5.x (Velocity 4.x), so such calls would throw
     * {@link IncompatibleClassChangeError} on one of the two proxies. {@code BinaryTagIO}
     * exposes the same operation through a stable interface.
     */
    static void writeNbt(ByteBuf buf, BinaryTag tag) throws IOException {
        if (!(tag instanceof CompoundBinaryTag compound)) {
            throw new IOException("Dialog payloads must be compound tags, got " + tag.getClass().getSimpleName());
        }
        try (DataOutputStream out = new DataOutputStream(new ByteBufOutputStream(buf))) {
            BinaryTagIO.writer().writeNameless(compound, (java.io.DataOutput) out);
        }
    }

    static void writeVarInt(ByteBuf buf, int value) {
        int remaining = value;
        while ((remaining & ~0x7F) != 0) {
            buf.writeByte((remaining & 0x7F) | 0x80);
            remaining >>>= 7;
        }
        buf.writeByte(remaining);
    }

    static int readVarInt(ByteBuf buf) {
        int result = 0;
        int shift = 0;
        while (true) {
            if (!buf.isReadable()) {
                throw new IllegalArgumentException("VarInt truncated");
            }
            byte b = buf.readByte();
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
            shift += 7;
            if (shift > 35) {
                throw new IllegalArgumentException("VarInt too big");
            }
        }
    }

    static String readString(ByteBuf buf, int maxLength) {
        int length = readVarInt(buf);
        if (length < 0 || length > maxLength * 4 || length > buf.readableBytes()) {
            throw new IllegalArgumentException("Bad string length " + length);
        }
        String value = buf.toString(buf.readerIndex(), length, StandardCharsets.UTF_8);
        buf.skipBytes(length);
        return value;
    }

    /**
     * Parses the body of a serverbound {@code custom_click_action}: identifier, then the
     * VarInt-prefixed nameless NBT payload (TAG_End when the action carries no data).
     *
     * @return the click, or {@code null} when the identifier is not in the {@code veloauth} namespace
     */
    static DialogClick parseClick(ByteBuf body) throws IOException {
        String id = readString(body, 32_767);
        int colon = id.indexOf(':');
        String namespace = colon >= 0 ? id.substring(0, colon) : "minecraft";
        if (!DialogNbt.ACTION_NAMESPACE.equals(namespace.toLowerCase(Locale.ROOT))) {
            return null;
        }
        String path = colon >= 0 ? id.substring(colon + 1) : id;
        return new DialogClick(path, readClickPayload(body));
    }

    private static CompoundBinaryTag readClickPayload(ByteBuf body) throws IOException {
        if (!body.isReadable()) {
            return CompoundBinaryTag.empty();
        }
        // Wire format (1.21.6+): VarInt payload size, then a nameless NBT tag; TAG_End (0) = no payload.
        int length = readVarInt(body);
        if (length < 0 || length > MAX_CLICK_PAYLOAD || length > body.readableBytes()) {
            throw new IllegalArgumentException("Bad click payload length " + length);
        }
        ByteBuf block = body.readSlice(length);
        if (!block.isReadable()) {
            return CompoundBinaryTag.empty();
        }
        BinaryTag tag = readNbt(block);
        return tag instanceof CompoundBinaryTag compound ? compound : CompoundBinaryTag.empty();
    }

    /**
     * Reads a network ("nameless") NBT tag. Only compound payloads are meaningful for dialog
     * clicks (the client always sends a compound with one entry per input), everything else is
     * skipped and reported as {@code null}.
     */
    static BinaryTag readNbt(ByteBuf buf) throws IOException {
        byte typeId = buf.getByte(buf.readerIndex());
        if (typeId == 0) {
            buf.readByte();
            return null;
        }
        if (typeId != NBT_TYPE_COMPOUND) {
            // Non-compound payload: not something a dialog produces; ignore the remaining bytes.
            buf.skipBytes(buf.readableBytes());
            return null;
        }
        try (DataInputStream in = new DataInputStream(new ByteBufInputStream(buf))) {
            return BinaryTagIO.reader(MAX_CLICK_PAYLOAD).readNameless((java.io.DataInput) in);
        }
    }

    /** Netty handler placed right after Velocity's packet decoder. */
    private final class ClickInterceptor extends ChannelInboundHandlerAdapter {
        private final Consumer<DialogClick> listener;
        private final Consumer<ByteBuf> rawListener;
        private final Object connection;
        private final int protocol;

        private ClickInterceptor(Consumer<DialogClick> listener, Consumer<ByteBuf> rawListener,
                                 Object connection, int protocol) {
            this.listener = listener;
            this.rawListener = rawListener;
            this.connection = connection;
            this.protocol = protocol;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof ByteBuf raw && !(msg instanceof ByteBufHolder)) {
                if (rawListener != null) {
                    try {
                        rawListener.accept(raw.duplicate());
                    } catch (RuntimeException e) {
                        logger.debug("Raw packet listener failed: {}", e.toString());
                    }
                }
                // Velocity decodes custom_click_action in CONFIG only; in PLAY it passes through raw.
                DialogClick click = parsePlayClick(raw);
                if (click != null) {
                    ReferenceCountUtil.release(msg);
                    try {
                        listener.accept(click);
                    } catch (RuntimeException e) {
                        logger.warn("Dialog click handler failed", e);
                    }
                    return;
                }
            }
            if (customClickClass.isInstance(msg) && msg instanceof ByteBufHolder holder) {
                DialogClick click = null;
                boolean ours = false;
                try {
                    ByteBuf body = holder.content().duplicate();
                    click = parseClick(body);
                    ours = click != null;
                } catch (IOException | RuntimeException e) {
                    logger.debug("Ignoring malformed custom click action: {}", e.toString());
                }
                if (ours) {
                    ReferenceCountUtil.release(msg);
                    try {
                        listener.accept(click);
                    } catch (RuntimeException e) {
                        logger.warn("Dialog click handler failed", e);
                    }
                    return;
                }
            }
            ctx.fireChannelRead(msg);
        }

        private DialogClick parsePlayClick(ByteBuf raw) {
            try {
                if (!statePlay.equals(connectionGetState.invoke(connection))) {
                    return null;
                }
                ByteBuf body = raw.duplicate();
                if (readVarInt(body) != playCustomClickId(protocol)) {
                    return null;
                }
                return parseClick(body);
            } catch (Throwable notOurs) {
                return null;
            }
        }

        @Override
        public boolean isSharable() {
            return false;
        }
    }
}
