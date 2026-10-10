package net.rafalohaki.veloauth.premium;

import io.netty.buffer.ByteBuf;
import javax.annotation.Nullable;

/**
 * Decoded serverbound {@code chat_session_update} ("Player Session") packet body.
 * <p>
 * Wire format (PLAY, 1.19.3+): session UUID, expiry (long), public key (VarInt-prefixed bytes,
 * max 512), Mojang signature (VarInt-prefixed bytes, max 4096). The packet id differs between
 * game versions, so the parser identifies the packet structurally: a raw serverbound packet whose
 * body matches this layout exactly, and whose signature later verifies against Mojang's key, is
 * the session packet - no other vanilla packet can satisfy both conditions.
 *
 * @param expiresAt key expiry in epoch milliseconds
 * @param publicKey X.509 encoded RSA public key
 * @param signature Mojang signature over {@code profile + expiry + key}
 */
public record ProfileKeyPacket(long expiresAt, byte[] publicKey, byte[] signature) {

    private static final int MAX_KEY = 512;
    private static final int MAX_SIGNATURE = 4096;
    private static final int UUID_BYTES = 16;

    /**
     * Tries to decode a raw serverbound packet (reader index at the packet id). Never throws;
     * returns {@code null} unless the body matches the session layout exactly.
     */
    @Nullable
    public static ProfileKeyPacket tryParse(ByteBuf raw) {
        return tryParse(raw, -1);
    }

    /**
     * Like {@link #tryParse(ByteBuf)} but additionally requires the packet id to equal
     * {@code expectedId} (pass a negative value to accept any id).
     */
    @Nullable
    public static ProfileKeyPacket tryParse(ByteBuf raw, int expectedId) {
        if (raw == null) {
            return null;
        }
        ByteBuf buf = raw.duplicate();
        try {
            int id = readVarInt(buf);
            if (id < 0 || (expectedId >= 0 && id != expectedId)) {
                return null; // packet id
            }
            if (buf.readableBytes() < UUID_BYTES + Long.BYTES + 2) {
                return null;
            }
            buf.skipBytes(UUID_BYTES);
            long expiresAt = buf.readLong();
            int keyLength = readVarInt(buf);
            if (keyLength <= 0 || keyLength > MAX_KEY || keyLength > buf.readableBytes()) {
                return null;
            }
            byte[] key = new byte[keyLength];
            buf.readBytes(key);
            int signatureLength = readVarInt(buf);
            if (signatureLength <= 0 || signatureLength > MAX_SIGNATURE || signatureLength != buf.readableBytes()) {
                return null;
            }
            byte[] signature = new byte[signatureLength];
            buf.readBytes(signature);
            return new ProfileKeyPacket(expiresAt, key, signature);
        } catch (RuntimeException malformed) {
            return null;
        }
    }

    /** Reads a VarInt; returns -1 when malformed. */
    static int readVarInt(ByteBuf buf) {
        int value = 0;
        int position = 0;
        while (true) {
            if (!buf.isReadable()) {
                return -1;
            }
            byte current = buf.readByte();
            value |= (current & 0x7F) << position;
            if ((current & 0x80) == 0) {
                return value;
            }
            position += 7;
            if (position >= 32) {
                return -1;
            }
        }
    }
}
