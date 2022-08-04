/* This code is a modification of slippery.c by Thomas Kaeding 2018-2019 in his paper */
/* Ranjit John 
This is a slippery hill-climbing method for ciphertext-only attack on
   Vigenere ciphers using a dictionary*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "tetragrams.h" /* tetragram frequencies */


#define MAXTEXTLEN    10000
#define MAXKEYLEN     100
#define IOCTHRESHOLD  1.65
#define IOCMULTTHRESH 1.2
#define MAX_LINES 65000
#define MAX_LEN 30

char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* the index of coincidence (IoC) for a text */
double index_of_coincidence(char* text) {
  int counts[26],total=0,i,length,numer=0;

  for (i=0;i<26;i++)
    counts[i] = 0;
  length = strlen(text);
  for (i=0;i<length;i++)
    counts[text[i]-'A']++;
  for (i=0;i<26;i++) {
    numer += counts[i]*(counts[i]-1);
    total += counts[i];
    }
  return (26.*numer)/(total*(total-1));
}


/* the decryption function for the polyalphabetic cipher */ //decrypt (c,p,pk,period);
void decrypt(char* c, char* p, char s[MAXKEYLEN], int keylen) {
  int length,i;

  length = strlen(c);
  p[length] = '\0';
  for(int i = 0; i< length; i++){
    p[i] = (((c[i] - s[i%keylen])+26)%26)+'A';
  }
    
  return;
  }

  /* the fitness of a text, based on tetragram frequencies */
double fitness(char *text) {
  int length,i,count=0;
  double result=0.;

  length = strlen(text);
  for (i=0;i<length-3;i++) {
    result += tetragrams[(text[i+0]-'A')*26*26*26
                        +(text[i+1]-'A')*26*26
                        +(text[i+2]-'A')*26
                        +(text[i+3]-'A')];
    count++;
    }
  return result/count;
  }

  /* copy the set of key alphabets */
void copy_keys(char source[MAXKEYLEN], char target[MAXKEYLEN],int keylen) {
    int i,j;
    for (i=0;i<keylen;i++){
        target[i] = source[i];
    }
    return;
}

/* swap two random characters in an alphabet */
void random_swap(char s[MAXKEYLEN]) {
    int i,j;
    char temp;
    i = j = random()%strlen(s);
    if(strlen(s) > 1){
        while (i == j){
            j = random()%strlen(s);
            if(s[i] == s[j]){
                j = random()%strlen(s);
            }
        }
    }
    temp = s[i];
    s[i] = s[j];
    s[j] = temp;
    return;
}

int factorial(int num){
  int fact = 1;
  for(int i=1;i<=num;i++){    
      fact=fact*i;    
  }    
  return fact;
}

int main(int argc, char** argv) {
    char c[MAXTEXTLEN];          /* the ciphertext                 */
    char p[MAXTEXTLEN];          /* the plaintext                  */
    char slice[MAXTEXTLEN];      /* one slice of ciphertext        */
    char bestp[MAXTEXTLEN];      /* best plaintext so far          */
    char pk[MAXKEYLEN];      /* the parent key alphabets       */
    char ck[MAXKEYLEN];      /* the child key alphabets        */
    char bestk[MAXKEYLEN];   /* best keys so far               */
    double fitp;                 /* fitness of parent              */
    double fitc;                 /* fitness of child               */
    double bestf;                /* best fitness so far            */
    double ioc;                  /* index of coincidence           */
    double oldioc=99.;           /* previous IoC                   */
    long int count,bigcount=0;   /* counters for loops             */
    int period=0;                /* period of the cipher           */
    int i,j,k;
    int length;                  /* length of the ciphertext       */
    int found=0;                 /* have we found the period?      */
    char outfileName [MAXTEXTLEN];
    strcpy(c,argv[1]); //ciphertext
    //period = atoi(argv[2]); // if you want to pass the period through as an argument
    strcpy(outfileName,argv[2]); //outputfile name to write results
    length = strlen(c);

    srandom(time(0));

    double time_spent = 0.0;
    clock_t begin = clock();

    /* find the period and cut the ciphertext into slices */
    while (!found) {
    period++;
    ioc = 0.;
    for (i=0;i<period;i++) {
        for (j=0;j<length/period;j++) {
        slice[j] = c[period*j+i];
        }
        slice[j] = '\0';
        ioc += index_of_coincidence(slice);
        }
    ioc /= period;
   
    if ((ioc > IOCTHRESHOLD) && (ioc > IOCMULTTHRESH*oldioc))
        found = 1;
    oldioc = ioc;
    }

    if(period < 2 || period > MAX_LEN){
    printf("\nNon-Optimal Period!");
    return 1;
  }


    FILE *file;
    file = fopen("output-onlinerandomtools.txt", "r"); //read the dictionary file
    char data[MAX_LINES][MAX_LEN]; //array that will hold the m-letter words
  
  if (file == NULL)
  {
    printf("Error opening file.\n");
    return 1;
  }
  
  // line will keep track of the number of lines read so far from the file
  int line = 0;
  char *word;
  word = malloc(1000); 
  int l1 ;
  
  //serach for all m-letter words in the dictionary and add to an array called data
  while (fscanf(file,"%s",word)!=EOF){
    l1 = strlen(word);
    if (l1 == period){
        sscanf(word, "%s", &data[line]);
        line++;
    }
    }
      
  
  // Close the file when we are done working with it.
  fclose(file);

  int min_iterations = 1000;
  int max_iterations = 100*line;

  if(period < 7){
    min_iterations = factorial(period);
    if(max_iterations > 1000000){
      max_iterations = max_iterations/10;
    }
    
  }
  else if(period > 7 && line > 8000 && line < 10000){
    min_iterations = line/10;
    max_iterations = 50*line;
  }

  if(max_iterations > 1000000){
    max_iterations = 1000000;
  }
    int r = random()%line;
    copy_keys(data[r], pk, period); //randomly pick initial m-letter word
  

    decrypt (c,p,pk,period);
    bestf = fitness(p);
  

    while (bigcount < max_iterations){
        r = random()%line;
        copy_keys(data[r], pk, period); //randomly pick new m-letter word

        decrypt(c,p,pk,period);
        fitp = fitness(p);
        count = 0;
        
        while (count < min_iterations) { 
            copy_keys(pk,ck,period);
            random_swap(ck);
            
            decrypt(c,p,ck,period);
            fitc = fitness(p);
            if (fitc > fitp) {
                copy_keys(ck,pk,period);
                fitp = fitc;
                count = 0;
            }
            else{
                count++;
            }
            if (fitc > bestf) {
                copy_keys(ck,bestk,period);
                bestf = fitc;
                bigcount = 0;
                strcpy(bestp,p);
            }
            else{
                bigcount++;
            }
            
        }      

    }
    clock_t end = clock();
    time_spent += (double)(end - begin)/CLOCKS_PER_SEC;
    file = fopen(outfileName, "a");
    
    //writing output to csv file
    fprintf(file,"%s, %s, %8.4f, %f, %f\n", bestp, bestk, bestf, time_spent, (time_spent/60));
    fclose(file);


    return 0;
  }