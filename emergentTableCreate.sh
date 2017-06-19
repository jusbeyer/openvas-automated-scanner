#~/bin/bash
DROP=false
while [[ $# -gt 1 ]]
do
key="$1"

case $key in
    --drop-table)
    DROP=true
    shift # past argument
    ;;
    -u|--username)
    USERNAME="$2"
    shift # past argument
    ;;
    -p|--password)
    PASSWORD="$2"
    shift # past argument
    ;;
    -db|--database)
    DATABASE="$2"
    shift # past argument
    ;;
    -t|--table)
    TABLE_NAME="$2"
    shift # past argument
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

if [[! $USERNAME]]
    then
	echo "You need to provide a username. Use -u or --username"
	exit
fi
if [[! $PASSWORD]]
    then
        echo "You might need a password....let's wait and see. If you do use -p or --password"
fi
if [[! $DATABASE]]
    then
        echo "You need to provide a database name to create the table in. Use -db or --database"
	exit
fi
if [[! $TABLE_NAME]]
    then
        echo "You need a name for the table. Use -t or --table"
	exit
fi

if [[$DROP]]
then 
	echo "Dropping the table...if it doesn't exist it might spit out some errors"
	echo `echo "DROP TABLE $TABLE_NAME"|mysql -u$USERNAME -p$PASSWORD $DATABASE`
fi

COMMAND="CREATE TABLE \`$TABLE_NAME\` (\`ip\` varchar(255) NOT NULL DEFAULT \'\', \`mac\` varchar(255) DEFAULT NULL, \`os\` varchar(255) DEFAULT NULL, \`scanned\` tinyint(1) DEFAULT \'0\', \`last_seen\` datetime DEFAULT NULL, \`hostname\` varchar(255) DEFAULT NULL, \`exclude\` tinyint(1) DEFAULT \'0\', \`id\` int(11) NOT NULL AUTO_INCREMENT, PRIMARY KEY (\`id\`)) ENGINE=InnoDB DEFAULT CHARSET=latin1"
echo "Running the create table command"
echo `echo $COMMAND|mysql -u$USERNAME -p$PASSWORD $DATABASE`
echo "All Done....Go check the database and make sure it worked."
