/*
** oraw.c
**
** Affiche les connexions a la base designee par ORACLE_SID
** (seules les connexions ne correpondant pas a des demons ora_xxx_SID
** sont affiches).
**
** compte ORACLE de connexion = variable env. ORAUSER
** mot de passe de connexion ORACLE = variable env. ORAPASSWD
**  
** 
*/

#include <stddef.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oci.h"


static OCIEnv *envhp;
static OCIServer *srvhp;
static OCIError *errhp; 
static OCISvcCtx *svchp;
static OCIStmt *stmthp;

static OCIDefine *defnp1 = (OCIDefine *)0;
static OCIDefine *defnp2 = (OCIDefine *)0;
static OCIDefine *defnp3 = (OCIDefine *)0;
static OCIDefine *defnp4 = (OCIDefine *)0;
static OCIDefine *defnp5 = (OCIDefine *)0;
static OCIDefine *defnp6 = (OCIDefine *)0;
static OCIDefine *defnp7 = (OCIDefine *)0;
static OCIDefine *defnp8 = (OCIDefine *)0;
static OCIDefine *defnp9 = (OCIDefine *)0;
static OCIDefine *defnp10 = (OCIDefine *)0;

static char username[30];
static char password[30];
static char db[20];
/*
 Pas de ; sinon ORA-911 
*/
static text *qs = (text *)"select substr(username, 1, 10),  substr(osuser, 1, 10), substr(machine, 1, 8), to_char (logon_time,'HH24:MI:SS'), status, audit_actions.name from v$session, audit_actions where username is not null and command = audit_actions.action order by username, osuser, logon_time";                                   

/* allouer char[l+1] pour le `\0` apres les 'l' char ... */
static char orauser[11];
static char osuser[11];
static char machine[9];
static char heure[9];
static char program[13];
static char sid[4];
static char serial[6]; 
static char taddr[9];
static char sstatus[10];
static char command[28] = "";
static char scommand[20];
static sword status;
static int indic;

static char *orauserenv = (char *)0;
static char *orapasswdenv = (char *)0;
static char *oracle_sidenv = (char *)0;

static void checkerr(OCIError *errp, sword cr, char *caller);
static void logon();
static void logoff();
static void execqr();

int main(int argc, char **argv)
{

	
        orauserenv = getenv("ORAUSER");
	if (orauserenv == (char *)0)
	{
		printf("ORAUSER non defini \n");
		exit (1); 
	}
        orapasswdenv = getenv("ORAPASSWD");
	if (orapasswdenv == (char *)0)
	{
		printf("ORAPASSWDENV non defini \n");
		exit (1); 
	}

        oracle_sidenv = getenv("ORACLE_SID");
	if (oracle_sidenv == (char *)0)
	{
		printf("ORACLE_SID non defini \n");
		exit (1); 
	}


	strcpy(username, orauserenv);
	strcpy(password, orapasswdenv);
	/* 
	** pour acces a base distante via Net8, utilisation
	** de "db" obligatoire dans OCILogon.
	*/
        strcpy(db, oracle_sidenv);
	logon();
	execqr();
	logoff();

}

void checkerr(errhp, status, caller)
OCIError *errhp;
sword status;
char *caller;
{
  text errbuf[512];
  sb4 errcode = 0;
  int ok=0;

  if (status != OCI_SUCCESS && status != OCI_SUCCESS_WITH_INFO)
 	 printf("%s:\n", caller); 
  switch (status)
  {
  case OCI_SUCCESS:
    ok = 1;
    break;
  case OCI_SUCCESS_WITH_INFO:
    /* (void) printf("Error - OCI_SUCCESS_WITH_INFO\n"); */                    
    ok= 1;
    break;
  case OCI_NEED_DATA:
    (void) printf("Error - OCI_NEED_DATA\n");
    break;
  case OCI_NO_DATA:
    (void) printf("Error - OCI_NO_DATA\n");
    break;
  case OCI_ERROR:
    (void) OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode,
                        errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
    (void) printf("Error - %.*s\n", 512, errbuf);
    break;
  case OCI_INVALID_HANDLE:
    (void) printf("Error - OCI_INVALID_HANDLE\n");
    break;
  case OCI_STILL_EXECUTING:
    (void) printf("Error - OCI_STILL_EXECUTE\n");
    break;
  case OCI_CONTINUE:
    (void) printf("Error - OCI_CONTINUE\n");
    break;
  default:
    break;    
   }
  if (ok == 0)
  {
	logoff();
	exit(1);
  }
}
 
void logon()
{

	status = OCIEnvCreate(&envhp, OCI_THREADED|OCI_OBJECT,
                 (dvoid *)0, 0, 0, 0, (size_t) 0, (dvoid **)0);
	checkerr(errhp, status, "OCIEnvcreate");
	
	status = OCIHandleAlloc((dvoid *)envhp, (dvoid **)&svchp,
                 OCI_HTYPE_SVCCTX, 0, (dvoid **)0);
	checkerr(errhp, status, "OCIHandleAlloc svchp");

	status = OCIHandleAlloc((dvoid *)envhp, (dvoid **)&errhp,
                 OCI_HTYPE_ERROR, 0, (dvoid **)0);
	checkerr(errhp, status,"OCIHandleAlloc errhp");

	/*
	** si db est vide, connection a $ORACLE_SID
	*/
	status = OCILogon(envhp, errhp, &svchp, 
                 (unsigned char*)username, strlen(username), 
                 (unsigned char*)password, strlen(password), 
                 (unsigned char*)db, strlen(db)); 
	checkerr(errhp, status, "OCILogon");
	
}

void execqr()
{

	status = OCIHandleAlloc((dvoid *)envhp, (dvoid **)&stmthp ,
                       OCI_HTYPE_STMT, (size_t)0, (dvoid **) 0);
	checkerr(errhp, status, "OCIHandleAlloc stmthp");

	status = OCIStmtPrepare(stmthp, errhp, qs, (ub4) strlen((char *)qs),
                  (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
	checkerr(errhp, status, "OCIStmtPrepare");
	
        status = OCIDefineByPos(stmthp, &defnp1, errhp, 1, (dvoid *) &orauser,
                 (sword)sizeof(orauser)-1 , SQLT_AFC, (dvoid *)0, (ub2 *) 0,
                 (ub2 *)0, OCI_DEFAULT); 
	checkerr(errhp, status, "OCIDefineByPos (orauser)");

        status = OCIDefineByPos(stmthp, &defnp2, errhp, 2, (dvoid *) &osuser,
                 (sword)sizeof(osuser)-1, SQLT_AFC, (dvoid *)0, (ub2 *) 0,
                 (ub2 *)0, OCI_DEFAULT); 
	checkerr(errhp, status, "OCIDefineByPos (osuser)");

        status = OCIDefineByPos(stmthp, &defnp3, errhp, 3, (dvoid *) &machine,
                 (sword)sizeof(machine)-1, SQLT_AFC, (dvoid *)0, (ub2 *) 0,
                 (ub2 *)0, OCI_DEFAULT); 
	checkerr(errhp, status, "OCIDefineByPos (machine)");

        status = OCIDefineByPos(stmthp, &defnp4, errhp, 4, (dvoid *) &heure,
                 (sword)sizeof(heure)-1, SQLT_AFC, (dvoid *)0, (ub2 *) 0,
                 (ub2 *)0, OCI_DEFAULT); 
	checkerr(errhp, status, "OCIDefineByPos (heure)");

        status = OCIDefineByPos(stmthp, &defnp5, errhp, 5, (dvoid *) &sstatus,
                 (sword)sizeof(sstatus)-1, SQLT_AFC, (dvoid *)0, (ub2 *) 0,
                 (ub2 *)0, OCI_DEFAULT); 
	checkerr(errhp, status, "OCIDefineByPos (sstatus)");

        status = OCIDefineByPos(stmthp, &defnp6, errhp, 6, (dvoid *) &command,
                 (sword)sizeof(command)-1, SQLT_AFC, (dvoid *)0, (ub2 *) 0,
                 (ub2 *)0, OCI_DEFAULT); 
	checkerr(errhp, status, "OCIDefineByPos (command)");

	status = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 0, (ub4) 0,
                 (const OCISnapshot *) NULL, (OCISnapshot *) NULL,
                 OCI_DEFAULT);
	checkerr(errhp, status, "OCIStmtExecute");

        printf("user        os user     machine   time      status    command \n");    
        printf("----------- ----------- --------- --------  --------  -----------\n");    
	while (1)
	{
		status = OCIStmtFetch(stmthp, errhp, (ub4) 1, OCI_FETCH_NEXT,
                         OCI_DEFAULT);
		if (status == OCI_SUCCESS || status == OCI_SUCCESS_WITH_INFO)
                {
		  strncpy(scommand, command, 28);
		  printf("%s  %s  %s  %s  %s %s\n", orauser, osuser, machine, heure, sstatus, scommand);
			    /* variable taddr non MAJ par OCIStmtFetch ?*/
 
                }
                else if (status == OCI_NO_DATA)	
			break;
		else	checkerr(errhp, status, "OCIStmtFetch");
	}	
}


void logoff()
{
 	status = OCILogoff(svchp, errhp);	
}
