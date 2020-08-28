#include <stdio.h>
#include <stdlib.h>
#include<time.h>

#include "../params.h"
#include "../xmss.h"
#include "../utils.h"

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_SIGN_OPEN xmssmt_sign_open
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_SIGN_OPEN xmss_sign_open
#endif

int main(int argc, char **argv) {
    FILE *keypair_file;
    FILE *sm_file;

    xmss_params params;
    uint32_t oid = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

    unsigned long long smlen;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "Expected keypair and signature + message filenames "
                        "as two parameters.\n"
                        "Keypair file needs only to contain the public key.\n"
                        "The return code 0 indicates verification success.\n");
        return -1;
    }

    keypair_file = fopen(argv[1], "rb");
    if (keypair_file == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    sm_file = fopen(argv[2], "rb");
    if (sm_file == NULL) {
        fprintf(stderr, "Could not open signature + message file.\n");
        fclose(keypair_file);
        return -1;
    }

    /* Find out the message length. */
    fseek(sm_file, 0, SEEK_END);
    smlen = ftell(sm_file);

    fread(&buffer, 1, XMSS_OID_LEN, keypair_file);
    oid = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        fclose(keypair_file);
        fclose(sm_file);
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char *sm = malloc(smlen);
    unsigned char *m = malloc(smlen);
    unsigned long long mlen;

    fseek(keypair_file, 0, SEEK_SET);
    fseek(sm_file, 0, SEEK_SET);
    fread(pk, 1, XMSS_OID_LEN + params.pk_bytes, keypair_file);
    fread(sm, 1, smlen, sm_file);
    
     /* 
    * STAR timer
    */
    
	//Abertura do arquivo que vai receber o tempo de criação das chaves
	FILE *file_time = fopen("Time to mult verify.txt", "a"); 
	
	//Verificação se o arquivo abriu
	if (file_time == NULL){
		printf("Erro para abrir o arquivo!\n");
		return -1;
	}
	
	//Abertura do arquivo que vai receber o clock para a criação das chaves
	FILE *file_time1 = fopen("Clock to mult verify.txt", "a"); 
	
	//Verificação se o arquivo abriu
	if (file_time1 == NULL){
		printf("Erro para abrir o arquivo!\n");
		return -1;
	}	
	
	long long int nun_clock;
	double time_spent = 0.0; //Varaiável que receberá o valor do tempo de execução
	clock_t begin = clock(); //Comça a contagem de operações de máquina
    /*
    * Will cont time to execute XMSS_SIGN_OPEN
    */
    
    ret = XMSS_SIGN_OPEN(m, &mlen, sm, smlen, pk);
    
     /*
    * STOP timer
    */
    fclose(stdout);

	clock_t end = clock(); //Para a contagem de operações
	
	time_spent +=(double)(end - begin) / CLOCKS_PER_SEC; //Divide a quantidades de operações pela frequência do clock para obter o tempo em segundo
	
	nun_clock =(long long int)(end - begin);
	
	// Regista no arquivo o tempo para criação do arquivo
	fprintf(file_time,"%lf;", time_spent);
	
	// Regista no arquivo o clock para criação do arquivo
	fprintf(file_time1,"%lld;", nun_clock);
	
	//Fecha os arquivos
	fclose(file_time);
	fclose(file_time1);
    /*
    * Save time and clock in .txt
    */
    
    if (ret) {
        printf("Verification failed!\n");
    }
    else {
        printf("Verification succeeded.\n");
    }

    fclose(keypair_file);
    fclose(sm_file);

    free(m);
    free(sm);

    return ret;
}
