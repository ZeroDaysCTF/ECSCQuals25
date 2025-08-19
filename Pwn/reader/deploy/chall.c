#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

long long arr[24];

void process_feedback() {
    char buffer[32];
    int length;
    
    printf("how long will your feedback be: ");
    scanf("%d", &length);
    printf("feedback: ");
    
    if (length > 0) {
        getchar(); // consume newline
        fread(buffer, 1, length, stdin);
    }
    
}

int main() {
    int idx;
    long long data;
    void *address;

    printf("enter the location you wish to read from\n");
    printf(">> ");
    scanf("%d", &idx);
    printf("found 0x%llx @ [%d] \n",arr[idx],idx);
    
    printf("send to >> ");
    scanf("%p", &address);
    printf("data? >> ");
    scanf("%lld", &data);
    *(long long*)address = data;
    
    process_feedback();
    
}