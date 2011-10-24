#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "md5.h"

#define LINE_LEN 16

struct user_info{
	u_char dmac[6],smac[6];
	int ip[4],mask[4],gateway[4];
	char username[50],password[50],version[100];
	int adapt;
};
pcap_t *fp;

void start_auth(struct user_info);
void print_packet(char *,int);
void make_md5(char *,int,char *);
void make_pw(int,char [],char[],char []); 
void send_pw(struct user_info,char *);
int send_data(char *,int);

void make_md5(char *input,int len,char *out){
	MD5_CTX p1;
    MD5Init(&p1);
    MD5Update(&p1,input,len);
    MD5Final(out,&p1);
	return;
}

void make_pw(int id,char password[],char key[16],char out[16]){
	char mystr[200];
	int i,j;
	memset(mystr,0,200);
	mystr[0] = id;
	for(i=0;i<strlen(password);i++)
		mystr[i+1] = password[i];
	i = 1+strlen(password);
	for(j=0;j<16;j++)
		mystr[i++] = key[j];
	make_md5(mystr,i,out);
	return;
}


struct user_info auth_init(){
	FILE * fp2;
	struct user_info user;
	int i;
	u_char i_tem1,i_tem2;
	char temp[20];
	if(! (fp2 = fopen("data.txt","r")) ){
		printf("请在本目录下新建data.txt文件,且写入相应的信息!\n");
		return;
	}
	fscanf(fp2,"%s",user.username);
	fscanf(fp2,"%s",user.password);
	fscanf(fp2,"%d.%d.%d.%d",&user.ip[0],&user.ip[1],&user.ip[2],&user.ip[3]);
	fscanf(fp2,"%d.%d.%d.%d",&user.mask[0],&user.mask[1],&user.mask[2],&user.mask[3]);
	fscanf(fp2,"%d.%d.%d.%d\n",&user.gateway[0],&user.gateway[1],&user.gateway[2],&user.gateway[3]);
	for(i=0;i<13;i++)
		fscanf(fp2,"%c",&temp[i]);
	for(i=0;i<13;i++)
		fscanf(fp2,"%2x",&user.version[i]);
	fscanf(fp2,"%d",&user.adapt);
	for(i=0;i<12;i++){
		i_tem1 = (temp[i] >= '0' && temp[i] <='9') ? (temp[i]-'0'):(temp[i]-'a'+10);
		if( i%2 == 0)
			i_tem2 = i_tem1;
		else{
			i_tem2 = i_tem2 * 16 + i_tem1;
			user.smac[i/2] = i_tem2;
		}
	}
	user.dmac[0] = 0x01;
	user.dmac[1] = 0x80;
	user.dmac[2] = 0xc2;
	user.dmac[3] = 0x00;
	user.dmac[4] = 0x00;
	user.dmac[5] = 0x03;
	fclose(fp2);
	printf("version: %s\n",user.version);
	return user;
}

int send_data(char *p,int len){
	if (pcap_sendpacket(fp,p,len) != 0){
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return 0;
	}
	return 1;
}

void start_auth(struct user_info user){
	u_char mess[100];
	int i;
	memset(mess,0,sizeof(mess));
	for (i=0;i<6;i++){
		mess[i] = user.dmac[i];
		mess[i+6] = user.smac[i];
	}
	mess[12] = 0x88;
	mess[13] = 0x8e;
	mess[14] = 0x01;
	mess[15] = 0x01;
	mess[16] = 0x00;
	mess[17] = 0x00;
	for(i=18;i<64;i++)
		mess[i] = 0xa5;
 	send_data(mess,64);
	return ;
}

void logoff(struct user_info user){
	u_char mess[100];
	int i;
	memset(mess,0,sizeof(mess));
	for(i=0;i<6;i++){
		mess[i] = user.dmac[i];
		mess[i+6] = user.smac[i];
	}
	mess[12] = 0x88;
	mess[13] = 0x8e;
	mess[14] = 0x01;
	mess[15] = 0x02;
	mess[16] = 0x00;
	mess[17] = 0x00;
	for(i=18;i<64;i++)
		mess[i] = 0xa5;
 	send_data(mess,64);
	return ;
}


void send_user(struct user_info user){
	u_char mess[100];
	char md5_pass[16];
	int i,j;
	memset(mess,0,sizeof(mess));
	for(i=0;i<6;i++){
		mess[i] = user.dmac[i];
		mess[i+6] = user.smac[i];
	}
	mess[12] = 0x88;
	mess[13] = 0x8e;
	mess[14] = 0x01;
	mess[15] = 0x00;
	mess[16] = 0x00;
	mess[17] = strlen(user.username)+51;
	mess[18] = 0x02;
	mess[19] = 0x01;
	mess[20] = 0x00;
	mess[21] = strlen(user.username)+5;
	mess[22] = 0x01;
	for(i=0;i<strlen(user.username);i++)
		mess[23+i] = user.username[i];
	i += 23;
	mess[i++] = 0x00;
	for(j=0;j<4;j++)
		mess[i+j] = user.ip[j];
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = user.mask[j];
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = user.gateway[j];
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = 0x00;
	i += 4;
	make_md5(user.username,strlen(user.username),md5_pass);
	for(j=0;j<16;j++)
		mess[i+j] = md5_pass[j];
	i += 16;
	for(j=0;j<13;j++)
		mess[i+j] = user.version[j];
	i += 13;
	send_data(mess,i);
}


void send_pw(struct user_info user,char key[16]){
	u_char mess[220];
	char md5_pass[16],md5_key[16];
	int i,j,temp1,temp2;
	memset(mess,0,sizeof(mess));
	memset(md5_key,0,16);
	memset(md5_pass,0,16);
	for(i=0;i<6;i++){
		mess[i] = user.dmac[i];
		mess[i+6] = user.smac[i];
	}
	mess[12] = 0x88;
	mess[13] = 0x8e;
	mess[14] = 0x01;
	mess[15] = 0x00;
	mess[16] = 0x00;
	mess[17] = 0xc4;        //len1
	mess[18] = 0x02;
	mess[19] = 0x02;
	mess[20] = 0x00;
	mess[21] = 0x96;        //len2
	mess[22] = 0x04;
	mess[23] = 0x10;
	i = 24;
	make_pw(2,user.password,key,md5_key);
	for(j=0;j<16;j++)
		mess[i++] = md5_key[j];
	for(j=0;j<128;j++)
		mess[i++] = 0x00;
	mess[i++] = 0x00;
	for(j=0;j<4;j++)
		mess[i+j] = user.ip[j];
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = user.mask[j];
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = user.gateway[j];
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = 0x00;
	i += 4;
	make_md5(user.username,strlen(user.username),md5_pass);
	for(j=0;j<16;j++)
		mess[i+j] = md5_pass[j];
	i += 16;
	for(j=0;j<13;j++)
		mess[i+j] = user.version[j];
	i += 13;
	send_data(mess,i);
	return;
}

void send_con(struct user_info user,char key[4],u_char id){
	u_char mess[220];
	char md5_pass[16],md5_key[16],md5_tem[100];
	int i,j,temp1,temp2;
	memset(mess,0,sizeof(mess));
	memset(md5_key,0,16);
	memset(md5_pass,0,16);
	memset(md5_tem,0,sizeof(md5_tem));
	for(i=0;i<strlen(user.username);i++)
		md5_tem[i] = user.username[i];
	for(i=0;i<4;i++)
		md5_tem[strlen(user.username)+i] = key[i];

	// begin
	for(i=0;i<6;i++){
		mess[i] = user.dmac[i];
		mess[i+6] = user.smac[i];
	}
	mess[12] = 0x88;
	mess[13] = 0x8e;
	mess[14] = 0x01;
	mess[15] = 0x00;
	mess[16] = 0x00;
	mess[17] = 0x36;        //len1
	mess[18] = 0x02;
	mess[19] = id;         //id
	mess[21] = 0x15;     //len2
	mess[22] = 0xfa;
	i = 23;
	make_md5(md5_tem,strlen(user.username)+4,md5_key);
	for(j=0;j<16;j++)
		mess[i++] = md5_key[j];
	mess[i++] = 0x00;
	for(j=0;j<4;j++)
		mess[j+i] = user.ip[j];       //ip address 
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = user.mask[j];     // mask
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = user.gateway[j];     //gateway
	i += 4;
	for(j=0;j<4;j++)
		mess[i+j] = 0x00;
	i += 4;
	make_md5(user.username,strlen(user.username),md5_pass);
	for(j=0;j<16;j++)
		mess[i+j] = md5_pass[j];
	i+= 16;
	send_data(mess,i);
	return;
}

void print_packet(u_char * ss,int len){
	int i;
	for(i=0;i<len;i++)
		printf("%2x",ss[i]);
	printf("\n");
}

int main(int argc, char **argv){
	pcap_if_t *alldevs, *d;
	u_int inum, i=0,tem,temp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
    u_char mystr[200];
	u_char pw_key[16];
	struct user_info user;

	user = auth_init();

    /* The user didn't provide a packet source: Retrieve the local device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }
    
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s\n    ", ++i, d->name);

        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if (i==0)
    {
        fprintf(stderr,"No interfaces found! Exiting.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    inum = user.adapt;

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
   
    /* Jump to the selected adapter */
    for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    /* Open the device */
    if ( (fp= pcap_open(d->name,
                        100 /*snaplen*/,
                        PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                        20 /*read timeout*/,
                        NULL /* remote authentication */,
                        errbuf)
                        ) == NULL)
    {
			
        fprintf(stderr,"\nError opening adapter\n");
        return -1;
    }
	while(1){
		printf("\n");
		logoff(user);
		Sleep(50);
		start_auth(user);
		Sleep(50);
		send_user(user);
		printf("send username\n");
		while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
		{

			if(res == 0)
				continue;
			if(pkt_data[12]==0x88 && pkt_data[13]==0x8e){
				if (pkt_data[17] != 0x09 && pkt_data[18]==0x01 && pkt_data[19]==0x02 ){
					for(tem=24;tem<40;tem++)
						pw_key[tem-24] = pkt_data[tem];
					send_pw(user,pw_key);
					printf("send password\n");
				}
				else if (pkt_data[17] == 0x09 && pkt_data[18] == 0x01){
					for(tem=23;tem<27;tem++)
						pw_key[tem-23] = pkt_data[tem];
					send_con(user,pw_key,pkt_data[19]);
					printf("send heart beat packet.\n");
				}
				if (pkt_data[18] == 0x03 && pkt_data[19] == 0x02){
					printf("connect success\n");
				}
			}
		}
	}
	logoff(user);
    if(res == -1)
    {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }
    pcap_close(fp);
    return 0;
}