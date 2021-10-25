# 4.8 Rootkit Kernel

"Eu vou instalar módulos em você e vou fazer o que eu quiser!!!!" - Disse o (SER) Sigma's Rootkit Kernel para o Kernel 4.8 (Ainda completou dizendo: "E fica esperto hein Kernel 4.10!")

Então, as ações do código malicioso:

-> Irá copiar o /etc/passwd para o /tmp/passwd.
-> O processador (ser_process.c) vai carregar o módulo (ser_mod.c)
-> O módulo vai executar em segundo plano:
1 - Ocultar o ser_process do ls e do find.
2 - Oculta o processo, o PID, no ps, ls /proc...
3 - Vai esconder as modificações pro /etc/passwd. (cat /etc/passwd vai olhar normal.)
4 - lsmod não vai dedurar o módulo, :)


O programa entra em um loop infinito enquanto o módulo do kernel é carregado para que o comportamento acima possa ser testado. Inserir o caractere 'q' interromperá o loop infinito e descarregará o módulo do kernel. 

Pra testar, basta executar o ser_process.c como administrador.

De maneira a agir de forma maliciosa, fica a seu critério, fiz esse Rootkit em um momento de tédio. Mas a base está aí.

