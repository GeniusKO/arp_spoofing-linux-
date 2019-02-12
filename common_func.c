#include "common_func.h"

int popen_comm_func(char *cmd, char *buf, size_t buf_len) {
    FILE *fp = NULL;

    memset(buf, 0x00, buf_len);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("errno : ");
        exit(0);
    }

    char *p = buf;
    int len = 0;
    int remain = buf_len;

    while (!feof(fp) && remain > 0)  {
        len = fread(p, 1, remain, fp);
        p+=len;
        remain -= len;
    }
    *p = 0;
    pclose(fp);

    return len;
}
