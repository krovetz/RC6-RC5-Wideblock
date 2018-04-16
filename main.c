/* Simple program for printing test vectors for RC5/RC6. 10APR2018 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "rc6.h"

/* In many C compilers, if the RC5/RC6 implementation declares a
 * global "vectors" too, then the linker will merge them into a
 * single global variable. Setting it in this file will be reflected
 * in the other. If it's not declared there, then it's setting here
 * has no effect.
 */
int vectors;

static void pbuf(const void *p, int len, const void *s)
{
    int i;
    if (s)
        printf("%s", (char *)s);
    for (i = 0; i < len; i++)
        printf("%02X", ((unsigned char *)p)[i]);
    printf("\n");
}

void print_vector6(int w, int r, int b) {
    int j, bpw=w/8, bpb=4*bpw;    /* bytes per: word and block */
    unsigned char *rkey = (unsigned char *)malloc((2*r+4)*bpw);
    unsigned char *key = (unsigned char *)malloc(b);
    unsigned char *buf = (unsigned char *)malloc(bpb);
    for (j=0; j<b; j++)   key[j]=j;
    for (j=0; j<bpb; j++) buf[j]=j;
    printf("RC6-%d/%d/%d\n",w,r,b);
    pbuf(key, b, "Key:          ");
    pbuf(buf, bpb, "Block input:  "); 
    if (rc6_setup(rkey, w, r, b, key))
        printf("Unsupported w/r/b: %d/%d/%d\n", w, r, b);
    else
        rc6_encrypt(rkey, w, r, buf, buf);
    pbuf(buf, bpb, "Block output: ");
    rc6_decrypt(rkey, w, r, buf, buf);
    pbuf(buf, bpb, "Block input:  "); 
    free(rkey); free(key); free(buf);
}

void print_vector5(int w, int r, int b) {
    int j, bpw=w/8, bpb=2*bpw;    /* bytes per: word and block */
    unsigned char *rkey = (unsigned char *)malloc((2*r+2)*bpw);
    unsigned char *key = (unsigned char *)malloc(b);
    unsigned char *buf = (unsigned char *)malloc(bpb);
    for (j=0; j<b; j++)   key[j]=j;
    for (j=0; j<bpb; j++) buf[j]=j;
    printf("RC5-%d/%d/%d\n",w,r,b);
    pbuf(key, b, "Key:          ");
    pbuf(buf, bpb, "Block input:  "); 
    if (rc5_setup(rkey, w, r, b, key))
        printf("Unsupported w/r/b: %d/%d/%d\n", w, r, b);
    else
        rc5_encrypt(rkey, w, r, buf, buf);
    pbuf(buf, bpb, "Block output: ");
    rc5_decrypt(rkey, w, r, buf, buf);
    pbuf(buf, bpb, "Block input:  "); 
    free(rkey); free(key); free(buf);
}

int main() {
    print_vector5(64,16,16);
    print_vector6(64,20,16);
    print_vector5(64,252,255);
    print_vector6(64,252,255);
    /* vectors = 1; */
    /* print_vectors6(16,4,8); */
    return 0;
}
