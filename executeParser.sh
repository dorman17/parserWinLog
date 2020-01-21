#!/bin/bash
echo " " > output.log
echo "========================================================================";
echo "  _____                          __          ___       _                 ";
echo " |  __ \                         \ \        / (_)     | |                ";
echo " | |__) |_ _ _ __ ___  ___ _ __   \ \  /\  / / _ _ __ | |     ___   __ _ ";
echo " |  ___/ _\` | '__/ __|/ _ \ '__|   \ \/  \/ / | | '_ \| |    / _ \ / _\` |";
echo " | |  | (_| | |  \__ \  __/ |       \  /\  /  | | | | | |___| (_) | (_| |";
echo " |_|   \__,_|_|  |___/\___|_|        \/  \/   |_|_| |_|______\___/ \__, |";
echo "                                                                    __/ |";
echo "                                                                   |___/ ";
echo "Realizzato da Pastore, Pontrelli and Scavo                                  ";
echo "Universita degli studi di Bari - Laurea Magistrale Sicurezza Informatica";
echo "Docente: Ugo Lopez";
echo "=========================================================================";
echo " ";
echo " ";
echo "===================================================================================";
echo "PRIMA DI PROCEDERE ASSICURARSI DI AVER EFFETTUATO IL MOUNT DEL DISCO DA ANALIZZARE!";
echo "===================================================================================";

if command -v python2.7 &>/dev/null; then
    echo "Python 2.7 presente su questa macchina";
    echo "Python 2.7 presente su questa macchina">> output.log
else
    sudo apt-get install python2.7
fi

if python -c "import Evtx" &> /dev/null; then
    echo "Libreria python-evtx presente su questa macchina">> output.log
    echo "Libreria python-evtx presente su questa macchina";
else
    sudo apt-get install python-evtx
fi

echo " ";
echo "Scegliere la directory del disco che si vuole analizzare";
PS3="Scegliere un numero (uscita per terminare): "
options=( $(df --output=target) )
unset options[0]
unset options[1]

select filepath in "${options[@]}" "USCITA"
do
   if [ $filepath == "USCITA" ]; then
    exit; 
   fi
   echo "Scelto il path --> $filepath " >> output.log
   echo "Scelto il path --> $filepath ";
   echo "-------";
   echo "Scegliere il file da analizzare"
   PS3='Scegliere un numero (uscita per terminare): '
   opt=("Security" "System" )
   select nameFile in "${opt[@]}" "USCITA"
   do
	if [ $nameFile == "USCITA" ]; then
	exit; 
	fi
	echo "Scelto il file --> $nameFile.evtx " >> output.log 
	echo "Scelto il file --> $nameFile.evtx ";   
   
	DIRECTORY=`dirname $0`
	FILE=$DIRECTORY/$nameFile".evtx"
	echo "$FILE";
	
	#if [ -f "$FILE" ]; then
	#rm $DIRECTORY/$nameFile".evtx"
	#fi

#PERCORSO DI WINDOWS PER RECUPERARE IL FILE #SECURITY.EVTX
	cp $filepath/Windows/System32/winevt/Logs/$nameFile".evtx" $DIRECTORY/$nameFile".evtx"
	chmod 777 $DIRECTORY/$nameFile".evtx"

#FILE PYTHON PER LA CONVERSIONE EVTX
	python $DIRECTORY/evtxDumper_fusione.py -f $DIRECTORY/$nameFile".evtx" -o $DIRECTORY -n $nameFile >> output.log
	exit;
	done
 done
