#include <stdio.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/types.h>
#include <unistd.h>
#include <math.h>
#include <string.h>


netsnmp_session session, *ss;
netsnmp_pdu *pdu;
netsnmp_pdu *response;
oid anOID[MAX_OID_LEN];
size_t anOID_len;
netsnmp_variable_list *vars;
int status;

struct interfaces{
  char ipaddress[20];
  int ifIndex;
};

void init(char *ip, char *community)
{
  init_snmp("asn2");


  snmp_sess_init( &session);
  session.peername = strdup(ip);
  session.version = SNMP_VERSION_2c;
  session.community = community;
  session.community_len = strlen(session.community);

}

void snmpcommand(char *oid, int command)
{
  SOCK_STARTUP;
  ss = snmp_open(&session);
  if(!ss)
  {
    snmp_sess_perror("ack", &session);
    SOCK_CLEANUP;
    exit(1);
  }
  pdu = snmp_pdu_create(command);
    if (command == SNMP_MSG_GETBULK)
    {
      pdu->non_repeaters = 0;
      pdu->max_repetitions = 50;
    }
    anOID_len = MAX_OID_LEN;
    get_node(oid, anOID, &anOID_len);
    snmp_add_null_var(pdu, anOID, anOID_len);
    status = snmp_synch_response(ss,pdu, &response);
}

void snmpget(char* oid)
{
  snmpcommand(oid,SNMP_MSG_GET);
}

void snmpgetnext(char *oid)
{
  snmpcommand(oid,SNMP_MSG_GETNEXT);
}
void snmpgetbulk(char *oid)
{
  snmpcommand(oid, SNMP_MSG_GETBULK);
}

void cleanup()
{
  if(response)
  {
    snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;
  }
}

void handlemyErrors(int err)
{
  if(status == STAT_SUCCESS)
  {
    fprintf(stderr, "Error in packet\nReason: %s\n",snmp_errstring(response->errstat));
  }
  else if(status == STAT_TIMEOUT)
  {
    fprintf(stderr, "Timeout: No Response from %s\n", session.peername);
  }
  else
  {
    snmp_sess_perror("snmp", ss);
  }
}

char *parseIP(char *tmpIP)
{
  snprint_ipaddress(tmpIP, 50, vars, NULL,NULL,NULL);

  int len = strlen("IpAddress: ");
  int NL = strlen(tmpIP) - len;
  strncpy(tmpIP, tmpIP+len, NL);
  *(tmpIP + NL) = '\0';
  return tmpIP;
}

struct interfaces monitor;

void showInterfaces()
{
  int monitor_index = 0;
  struct interfaces ifInterface[10];
  char *oid = "ipAdEntAddr";
  int count = 0;
  snmpgetbulk(oid);
  printf("\n||===========================||");
  printf("\n||         Interfaces        ||");
  printf("\n||===========================||");
  printf("\n|| Number   |   IP           ||");
  printf("\n||========================== ||\n");
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)
  {
      for(vars = response->variables; vars; vars = vars->next_variable)
      {
        if(vars->type == (ASN_IPADDRESS))
        {
          char tmpIp[50];
          strcpy(ifInterface[count++].ipaddress, parseIP(tmpIp));
          int copy = strcmp(tmpIp, "localhost");
          if(copy!= 0)
          {
            monitor_index = count;
            strcpy(monitor.ipaddress, tmpIp);
          }
          if(count >= 10)
          {
            printf("Too many interfaces\n");
            vars = vars->next_variable;
            break;
          }
        }
        else
        {
          count = 0;
          break;
        }
      }
      for(vars; vars; vars = vars->next_variable)
      {
        if (vars->type == ASN_INTEGER)
        {
          ifInterface[count++].ifIndex = (int) *(vars->val.integer);
          if(count == monitor_index)
          {
            monitor.ifIndex = (int) *(vars->val.integer);
          }
          if(count >= 10)
          {
            printf("Too many interfaces\n");
            break;
          }
      }
      else
      {
        break;
      }
  }
}
else
{
  handlemyErrors(status);

}
cleanup();

count--;
while(count >= 0)
{
  printf("|| %i | %s ||\n", ifInterface[count].ifIndex, ifInterface[count].ipaddress);
  count--;
}

printf("=========================================================================\n");
printf("\n\n");
}



int main(int argc, char* argv[])
{
  if( argc != 5)
  {
    printf("Please provide Time interval between samples, Number of samples to take, IP address of the agent, and community\n");

  }

  int timeInterval = atoi(argv[1]);
  int numOfSamples = atoi(argv[2]);
  char *hostname = argv[3];
  char *community = argv[4];
  init(hostname,community);
  showInterfaces();

  return 0;
}
