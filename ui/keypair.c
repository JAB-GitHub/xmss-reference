#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "../params.h"
#include "../xmss.h"

#ifdef XMSSMT
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_KEYPAIR xmssmt_keypair
#else
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_KEYPAIR xmss_keypair
#endif

int main(int argc, char **argv)
{
    xmss_params params;
    uint32_t oid = 0;
    int parse_oid_result = 0;

    if (argc != 2) {
        fprintf(stderr, "Expected parameter string (e.g. 'XMSS-SHA2_10_256')"
                        " as only parameter.\n"
                        "The keypair is written to stdout.\n");
        return -1;
    }

    XMSS_STR_TO_OID(&oid, argv[1]);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    
    /* 
    * STAR timer
    */
    
	//Abertura do arquivo que vai receber o tempo de criação das chaves
	FILE *file_time = fopen("Time to mult keypair generacion.txt", "a"); 
	
	//Verificação se o arquivo abriu
	if (file_time == NULL){
		printf("Erro para abrir o arquivo!\n");
		return -1;
	}
	
	//Abertura do arquivo que vai receber o clock para a criação das chaves
	FILE *file_time1 = fopen("Clock to mult keypair generacion.txt", "a"); 
	
	//Verificação se o arquivo abriu
	if (file_time1 == NULL){
		printf("Erro para abrir o arquivo!\n");
		return -1;
	}	
	
	long long int nun_clock;
	double time_spent = 0.0; //Varaiável que receberá o valor do tempo de execução
	clock_t begin = clock(); //Comça a contagem de operações de máquina
    /*
    * Will cont time to execute XMSS_KEYPAIR
    */
    
    XMSS_KEYPAIR(pk, sk, oid);

    /*
    * STOP timer
    */
    fclose(stdout);

	clock_t end = clock(); //Para a contagem de operações
	
	time_spent +=(double)(end - begin) / CLOCKS_PER_SEC; //Divide a quantidades de operações pela frequência do clock para obter o tempo em segundo
	
	nun_clock = (long long int)(end - begin);
	
	// Regista no arquivo o tempo para criação do arquivo
	fprintf(file_time,"%lf;", time_spent);
	
	// Regista no arquivo o clock para criação do arquivo
	fprintf(file_time1,"%lld;", nun_clock);
	
	//Fecha os arquivos
	fclose(file_time);
	fclose(file_time1);
    /*
    * Save time and clo in .txt
    */
    
    fwrite(pk, 1, XMSS_OID_LEN + params.pk_bytes, stdout);
    fwrite(sk, 1, XMSS_OID_LEN + params.sk_bytes, stdout);

    fclose(stdout);

    return 0;
}
