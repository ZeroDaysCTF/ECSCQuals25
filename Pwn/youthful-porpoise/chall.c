#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NAME_LEN 64

char user_name[NAME_LEN] = "Guest";

void set_name() {
    char name[NAME_LEN];
    printf("Enter your name: ");
    scanf("%s", name);  // vulnerable

    strncpy(user_name, name, NAME_LEN - 1);
    user_name[NAME_LEN - 1] = '\0';

    printf("Hello, ");
    printf(user_name);
    printf("\n");
}

const char *wisdom_quotes[] = {
    "The only true wisdom is in knowing you know nothing. — Socrates",
    "Happiness depends upon ourselves. — Aristotle",
    "Be yourself; everyone else is already taken. — Oscar Wilde",
    "Do not dwell in the past, do not dream of the future, concentrate the mind on the present moment. — Buddha"
};

void daily_wisdom() {
    int num_quotes = sizeof(wisdom_quotes) / sizeof(wisdom_quotes[0]);
    int idx = rand() % num_quotes;
    printf("Daily Wisdom for %s:\n%s\n", user_name, wisdom_quotes[idx]);
}

int main() {
    int option;
    srand(time(NULL));
    printf("Welcome! Relax and enjoy some wisdom.\n");

    while (1) {
        printf("\n1. Set Name\n2. Daily Wisdom\n3. Quit\n> ");
        if (scanf("%d", &option) != 1) break;
        while(getchar() != '\n');

        if (option == 1) {
            set_name();
        } else if (option == 2) {
            daily_wisdom();
        } else {
            printf("Goodbye, %s! Stay relaxed.\n", user_name);
            break;
        }
    }
    return 0;
}