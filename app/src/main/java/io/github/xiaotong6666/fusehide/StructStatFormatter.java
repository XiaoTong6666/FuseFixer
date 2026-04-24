package io.github.xiaotong6666.fusehide;

import android.system.StructStat;

public abstract class StructStatFormatter {
    public static String format(StructStat structStat) {
        StringBuilder sb = new StringBuilder();
        int type = structStat.st_mode & 61440;
        if (type == 4096) {
            sb.append('p');
        } else if (type == 8192) {
            sb.append('c');
        } else if (type == 16384) {
            sb.append('d');
        } else if (type == 24576) {
            sb.append('b');
        } else if (type == 32768) {
            sb.append('-');
        } else if (type == 40960) {
            sb.append('l');
        } else if (type == 49152) {
            sb.append('s');
        } else {
            sb.append('?');
        }
        sb.append((structStat.st_mode & 256) != 0 ? 'r' : '-');
        sb.append((structStat.st_mode & 128) != 0 ? 'w' : '-');
        appendExec(sb, structStat.st_mode, 64, 2048, 's', 'S');
        sb.append((structStat.st_mode & 32) != 0 ? 'r' : '-');
        sb.append((structStat.st_mode & 16) != 0 ? 'w' : '-');
        appendExec(sb, structStat.st_mode, 8, 1024, 't', 'T');
        sb.append((structStat.st_mode & 4) != 0 ? 'r' : '-');
        sb.append((structStat.st_mode & 2) != 0 ? 'w' : '-');
        appendExec(sb, structStat.st_mode, 1, 512, 't', 'T');
        sb.append("\nInode: ").append(structStat.st_ino);
        sb.append("\nDevice: ");
        long dev = structStat.st_dev;
        sb.append(((dev >> 8) & 4095) | ((dev >>> 32) & 4294963200L));
        sb.append(',');
        sb.append((dev & 255) | ((dev >>> 12) & 4294967040L));
        sb.append("\nUid: ").append(structStat.st_uid);
        sb.append(" Gid: ").append(structStat.st_gid);
        return sb.toString();
    }

    private static void appendExec(StringBuilder sb, int mode, int execMask, int specialMask, char lower, char upper) {
        if ((mode & specialMask) == 0) {
            sb.append((mode & execMask) != 0 ? 'x' : '-');
        } else {
            sb.append((mode & execMask) != 0 ? lower : upper);
        }
    }
}
