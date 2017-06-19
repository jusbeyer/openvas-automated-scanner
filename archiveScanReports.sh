#!/bin/bash
BACKUP_DIRECTORY=$1
REPORTS_DIRECTORY=$2

dt=$(date +%F_%T);
date_var=$(date '+%m-%d-%Y');

ARCHIVE_DIR=$BACKUP_DIRECTORY'_'$date_var
echo $ARCHIVE_DIR
  echo 'Archiving PDF Scan Reports now'
  mkdir -p $ARCHIVE_DIR
  echo 'Made Backup Directory'
  tar vczf $ARCHIVE_DIR/scan_report-$dt.tar.gz $REPORTS_DIRECTORY
  rm -r $REPORTS_DIRECTORY && mkdir $REPORTS_DIRECTORY
