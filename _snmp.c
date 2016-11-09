#include <stdio.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/types.h>
#include <unistd.h>
#include <math.h>
#include <string.h>

#define lastInOctets 0
#define lastOutOctets 1


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
          char tmpIp[100];
          strcpy(ifInterface[count++].ipaddress, parseIP(tmpIp));

        //printf("Interface #: %s\n",ifInterface[count].ipaddress);
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
  printf("|| %i        | %s||\t\n", ifInterface[count].ifIndex, ifInterface[count].ipaddress);
  count--;
}
printf("=========================================================================\n");
}

void showNeighbor()
{
  char ifIndexOID[50] = "ipNetToMediaIfIndex";
  char ipOID[50] = "ipNetToMediaNetAddress";
  printf("\n||===========================||");
  printf("\n||         Neighbor          ||");
  printf("\n||===========================||");
  printf("\n|| Interface   |  Neighbor   ||");
  printf("\n||===========================||\n");
  while(1)
  {
    snmpgetnext(ifIndexOID);
    int index;
    char *ipAdd;
    vars = response->variables;

    if( vars->type == ASN_INTEGER)
    {
      char tmpIp[50];
      snprint_objid(tmpIp,50, vars->name, vars->name_length);
      strcpy(ifIndexOID, tmpIp);
      index = (int) *(vars->val.integer);
    }
    else
    {
      break;
    }
    cleanup();
    snmpgetnext(ipOID);
    vars = response->variables;
    if(vars->type == ASN_IPADDRESS)
    {
      char tmpIp2[50];
      char tmpOiD[50];
      snprint_objid(tmpOiD,50,vars->name,vars->name_length);
      strcpy(ipOID,tmpOiD);
      ipAdd = parseIP(tmpIp2);
    }
    else
    {
      break;
    }
    printf("|| %i           | %s ||\n",index, ipAdd);
    cleanup();
  }
  printf("=========================================================================\n");
}

void showTraffic(int interval, int samples)
{
  char *monitorIPtraffic = monitor.ipaddress;
  int data[2];
  char *ifInOctets[50];
  char *ifOutOctets[50];

  sprintf(ifInOctets, "%s.%i", "ifInOctets", monitor.ifIndex);
  sprintf(ifOutOctets, "%s.%i", "ifOutOctets", monitor.ifIndex);

  printf("Monitoring %s \n", monitorIPtraffic);

  snmpget(ifInOctets);
  data[lastInOctets] = (int) *(response->variables->val.integer);
  cleanup();
  snmpget(ifOutOctets);
  data[lastOutOctets] = (int) *(response->variables->val.integer);
  cleanup();

  int ttime = interval;
  while(samples >= 0)
  {
    sleep(interval);
    snmpget(ifInOctets);
    int inOctets = (int) *(response->variables->val.integer);
    cleanup();
    snmpget(ifOutOctets);
    int outOctets = (int) *(response->variables->val.integer);
    cleanup();

    long double traf = (fmax((inOctets - data[lastInOctets]),(outOctets - data[lastOutOctets]))) * (0.001)  / (interval);
    printf("At %i seconds --> %i kbps --> (%i mbps)\n", ttime, traf, traf);
    data[lastInOctets] = inOctets;
    data[lastOutOctets] = outOctets;
    ttime = ttime + interval;
    samples--;
  }
}


int main(int argc, char* argv[])
{
  if( argc != 5)
  {
    printf("Please provide Time interval between samples, Number of samples to take, IP address of the agent, and community\n");

  }

  int interval = atoi(argv[1]);
  int samples = atoi(argv[2]);
  char *hostname = argv[3];
  char *community = argv[4];
  init(hostname,community);
  showInterfaces();
  showNeighbor();
  showTraffic(interval, samples);
  return 0;
}
