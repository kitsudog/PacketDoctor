package pd.utils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class Colors
{
    private static final int COLORS[] = new int[]
    { 0xf7acbc, 0xdeab8a, 0x817936, 0x444693, 0xef5b9c, 0xfedcbd, //
            0x7f7522, 0x2b4490, 0xfeeeed, 0xf47920, 0x80752c, 0x2a5caa, //
            0xf05b72, 0x905a3d, 0x87843b, 0x224b8f, 0xf15b6c, 0x8f4b2e, //
            0x726930, 0x003a6c, 0xf8aba6, 0x87481f, 0x454926, 0x102b6a, //
            0xf69c9f, 0x5f3c23, 0x2e3a1f, 0x426ab3, 0xf58f98, 0x6b473c, //
            0x4d4f36, 0x46485f, 0xca8687, 0xfaa755, 0xb7ba6b, 0x4e72b8, //
            0xf391a9, 0xfab27b, 0xb2d235, 0x181d4b, 0xbd6758, 0xf58220, //
            0x5c7a29, 0x1a2933, 0xd71345, 0x843900, 0xbed742, 0x121a2a, //
            0xd64f44, 0x905d1d, 0x7fb80e, 0x0c212b, 0xd93a49, 0x8a5d19, //
            0xa3cf62, 0x6a6da9, 0xb3424a, 0x8c531b, 0x769149, 0x585eaa, //
            0xc76968, 0x826858, 0x6d8346, 0x494e8f, 0xbb505d, 0x64492b, //
            0x78a355, 0xafb4db, 0x987165, 0xae6642, 0xabc88b, 0x9b95c9, //
            0xac6767, 0x56452d, 0x74905d, 0x6950a1, 0x973c3f, 0x96582a, //
            0xcde6c7, 0x6f60aa, 0xb22c46, 0x705628, 0x1d953f, 0x867892, //
            0xa7324a, 0x4a3113, 0x77ac98, 0x918597, 0xaa363d, 0x412f1f, //
            0x007d65, 0x6f6d85, 0xed1941, 0x845538, 0x84bf96, 0x594c6d, //
            0xf26522, 0x8e7437, 0x45b97c, 0x694d9f, 0xd2553d, 0x69541b, //
            0x225a1f, 0x6f599c, 0xb4534b, 0xd5c59f, 0x367459, 0x8552a1, //
            0xef4136, 0xcd9a5b, 0x007947, 0x543044, 0xc63c26, 0xcd9a5b, //
            0x40835e, 0x63434f, 0xf3715c, 0xb36d41, 0x2b6447, 0x7d5886, //
            0xa7573b, 0xdf9464, 0x005831, 0x401c44, 0xaa2116, 0xb76f40, //
            0x006c54, 0x472d56, 0xb64533, 0xad8b3d, 0x375830, 0x45224a, //
            0xb54334, 0xdea32c, 0x274d3d, 0x411445, 0x853f04, 0xd1923f, //
            0x375830, 0x4b2f3d, 0x840228, 0xc88400, 0x27342b, 0x402e4c, //
            0x7a1723, 0xc37e00, 0x65c294, 0xc77eb5, 0xa03939, 0xc37e00, //
            0x73b9a2, 0xea66a6, 0x8a2e3b, 0xe0861a, 0x72baa7, 0xf173ac, //
            0x8e453f, 0xffce7b, 0x005344, 0xfffffb, 0x8f4b4a, 0xfcaf17, //
            0x122e29, 0xfffef9, 0x892f1b, 0xba8448, 0x293047, 0xf6f5ec, //
            0x6b2c25, 0x896a45, 0x00ae9d, 0xd9d6c3, 0x733a31, 0x76624c, //
            0x508a88, 0xd1c7b7, 0x54211d, 0x6d5826, 0x70a19f, 0xf2eada, //
            0x78331e, 0xffc20e, 0x50b7c1, 0xd3d7d4, 0x53261f, 0xfdb933, //
            0x00a6ac, 0x999d9c, 0xf15a22, 0xd3c6a6, 0x78cdd1, 0xa1a3a6, //
            0xb4533c, 0xc7a252, 0x008792, 0x9d9087, 0x84331f, 0xdec674, //
            0x94d6da, 0x8a8c8e, 0xf47a55, 0xb69968, 0xafdfe4, 0x74787c, //
            0xf15a22, 0xc1a173, 0x5e7c85, 0x7c8577, 0xf3704b, 0xdbce8f, //
            0x76becc, 0x72777b, 0xda765b, 0xffd400, 0x90d7ec, 0x77787b, //
            0xc85d44, 0xffd400, 0x009ad6, 0x4f5555, 0xae5039, 0xffe600, //
            0x145b7d, 0x6c4c49, 0x6a3427, 0xf0dc70, 0x11264f, 0x563624, //
            0x8f4b38, 0xfcf16e, 0x7bbfea, 0x3e4145, 0x8e3e1f, 0xdecb00, //
            0x33a3dc, 0x3c3645, 0xf36c21, 0xcbc547, 0x228fbd, 0x464547, //
            0xb4532a, 0x6e6b41, 0x2468a2, 0x130c0e, 0xb7704f, 0x596032, //
            0x2570a1, 0x281f1d, 0xde773f, 0x525f42, 0x2585a6, 0x2f271d, //
            0xc99979, 0x5f5d46, 0x1b315e, 0x1d1626 };

    public static final Colors DEFAULT = new Colors();

    private Map<String, Integer> map = new ConcurrentHashMap<String, Integer>();

    private AtomicLong cnt = new AtomicLong();

    public int getColor(String key)
    {
        if (!map.containsKey(key))
        {
            map.put(key, COLORS[(int) (cnt.incrementAndGet() % COLORS.length)]);
        }
        return map.get(key);
    }
}