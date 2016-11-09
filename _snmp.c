/*
 * Author: Omar Mousa, Ronald Cheng
 * Student ID#s: 006181240, 007810023
 *
 * Assignment : SNMP using C
 */
#include <stdio.h> // standard C library
#include <stdlib.h>
#include <net-snmp/net-snmp-config.h> //net-snmp configure library
#include <net-snmp/net-snmp-includes.h> // net-snmp includes library
#include <net-snmp/types.h>
#include <string.h>
#include <time.h>
#include <math.h>
/* determine the number of octets lost over the incoming link */
#define lastInOctets 0
/* determines number of octets lost over the outgoing link */
#define lastOutOctets 1

/* Global Variables for monitoring*/
netsnmp_session session, *ss;
netsnmp_pdu *pdu;
netsnmp_pdu *response;
oid anOID[MAX_OID_LEN];
size_t anOID_len;
netsnmp_variable_list *vars;
int status;

/* structure to grab ipaddresses as a string and ifIndex values */
struct interfaces{
  char ipaddress[20];
  int ifIndex;
};

/* initiating the snmp agent */
void init(char *ip, char *community)
{
  /* to initiate the snmp session */
  init_snmp("asn2");

/* Default set up */

  snmp_sess_init( &session);
  /* peername: name of default address */
  session.peername = strdup(ip);
  /* SNMP version used {SNMPv2c}*/
  session.version = SNMP_VERSION_2c;
  /* default community name */
  session.community = community;
  /* the length of the community name */
  session.community_len = strlen(session.community);

}

/* to establish an snmp session */
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
  /* for snmpbulkget operation */
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

/* snmpget operation */
void snmpget(char* oid)
{
  snmpcommand(oid,SNMP_MSG_GET);
}
/* snmpgetnext operation */
void snmpgetnext(char *oid)
{
  snmpcommand(oid,SNMP_MSG_GETNEXT);
}
/* snmpgetbulk operation {introduced in SNMPv2} */
void snmpgetbulk(char *oid)
{
  snmpcommand(oid, SNMP_MSG_GETBULK);
}
/* cleanup and release the pdus from V1 and V2 */
void cleanup()
{
  if(response)
  {
    snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;
  }
}
/* error handling function */
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
/* to parse through IP addresses */
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
/*||=============================================||
 *||                interfaces                   ||
 *||=============================================|| */
/* Shows the Agents Interfaces */

void showInterfaces()
{
  int monitor_index = 0;
  struct interfaces ifInterface[10];
  char *oid = "ipAdEntAddr";
  int count = 0;
  /* getbulk function to read oid of Agent */
  snmpgetbulk(oid);
  printf("\n||==============================||");
  printf("\n||         Interfaces           ||");
  printf("\n||==============================||");
  printf("\n|| Number     |   IP            ||");
  printf("\n||==============================||\n");

  /* there is No Error in snmp session */
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)
  {
      /* loop to read values of the variables within the session at the interface level */

      for(vars = response->variables; vars; vars = vars->next_variable)
      {
        /* If variable in netsnmp is type ASN it is a representation of IPaddresses */
        if(vars->type == (ASN_IPADDRESS))
        {
          /* a string of 50 to store the IP that was parsed for the Interfaces */
          char tmpIp[50];
          /* copy the ip address if it is considered an interface */

          strcpy(ifInterface[count++].ipaddress, parseIP(tmpIp));
          /* compare string with localhost IP address */
          int copy = strcmp(tmpIp, "localhost");
          /* if copy returns a non-zero copy ipaddress that is being monitored */
          if(copy!= 0)
          {
            monitor_index = count;
            strcpy(monitor.ipaddress, tmpIp);
          }
          /* takes in no more than 9 interfaces */
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
      /* loop to monitor ippaddress in the interface level */
      for(vars; vars; vars = vars->next_variable)
      {
        /* if ip string is a data representation of ASN monitor that address */
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
/* formating the output of the interfaces */
while(count >= 0)
{
  if(ifInterface[count].ifIndex > 9)
  {
  printf("||%i\t      |%s\t||\n", ifInterface[count].ifIndex, ifInterface[count].ipaddress);
  count--;
  }
  else
  {
    printf("||%i\t      |%s \t||\n", ifInterface[count].ifIndex, ifInterface[count].ipaddress);
    count--;
  }

}
  printf("||==============================||\n");
}
/*||=============================================||
 *||                Neighbors                    ||
 *||=============================================|| */
/* Show the agents Neighboring networks */
void showNeighbor()
{
  char ifIndexOID[50] = "ipNetToMediaIfIndex";
  char ipOID[50] = "ipNetToMediaNetAddress";
  printf("\n||==============================||");
  printf("\n||            Neighbor          ||");
  printf("\n||==============================||");
  printf("\n||Interface    |  Neighbor      ||");
  printf("\n||==============================||\n");
do
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

    if(index > 9)
    {
      printf("||%i\t       |%s   ||\n",index, ipAdd);
    }
    else
    {
      printf("||%i\t       |%s\t||\n",index, ipAdd);
    }
    cleanup();
  }while(1);
  printf("||==============================||\n");
}

/*||=============================================||
 *||                Monitoring                   ||
 *||=============================================|| */
/* Monitoring Internet Traffic */
void showTraffic(int interval, int samples)
{
  char *monitorIPtraffic = monitor.ipaddress;
  int data[2];
  char *ifInOctets[50];
  char *ifOutOctets[50];

  sprintf(ifInOctets, "%s.%i", "ifInOctets", monitor.ifIndex);
  sprintf(ifOutOctets, "%s.%i", "ifOutOctets", monitor.ifIndex);

  printf("||Monitoring %s\t||\n", monitorIPtraffic);

  snmpget(ifInOctets);
  data[lastInOctets] = (int) *(response->variables->val.integer);
  cleanup();
  snmpget(ifOutOctets);
  data[lastOutOctets] = (int) *(response->variables->val.integer);
  cleanup();

  int ttime = 0;
  while(samples >= 0)
  {
    sleep(interval);
    snmpget(ifInOctets);
    int inOctets = (int) *(response->variables->val.integer);
    cleanup();
    snmpget(ifOutOctets);
    int outOctets = (int) *(response->variables->val.integer);
    cleanup();
    /* monitoring the traffic going on the agent device */
    long double octets = fmax((inOctets - data[lastInOctets]),(outOctets - data[lastOutOctets]));
    long double traf = ((octets * 0.001)/interval) * (0.001);
    printf("At %i seconds | mbps = %i.%d\n", ttime, traf);
    data[lastInOctets] = inOctets;
    data[lastOutOctets] = outOctets;
    ttime = ttime + interval;
    samples--;
  }
}

/*||=============================================||
 *||                Main                         ||
 *||=============================================|| */
/* Main Function */
/* main function that takes commands on the Command Line Interface */
int main(int argc, char* argv[])
{
  if( argc != 5)
  {
    printf("Please provide Time interval, Number of samples, IP address of the agent, and community\n");

  }

  int interval = atoi(argv[1]);
  int samples = atoi(argv[2]);
  char *host = argv[3];
  char *community = argv[4];
  init(host,community);
  showInterfaces();
  printf("||==============================||");
  showNeighbor();
  printf("||==============================||\n");
  showTraffic(interval, samples);
  return 0;
}
