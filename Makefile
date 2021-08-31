#
# Makefile
#

oraw: oraw.c
	cc -o oraw -I$(ORACLE_HOME)/precomp/public -I$(ORACLE_HOME)/rdbms/public -L$(ORACLE_HOME)/lib -lclntsh oraw.c

clean:
	rm -f oraw 

