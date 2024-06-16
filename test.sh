#!/bin/sh

function check {
  npm run cli ~/test_bels/$1 > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "Success"
  else
    echo "Failed"
  fi
}

function run {
  npm run cli ~/test_bels/$1
}

check 0_WMMkkRwemGZJg2.A.2.1.bel
check 4NCgLpD6CTbGNR.bel
#check 7KSM7eYVYykSR4.bel
check LtrgPq4PVPJRck.unfinished.bel
#check fxR7qSGQDLXajU.bel
check 1_LtrgPq4PVPJRck.unfinished2.bel
check G5f9oSpSs1RZFw.bel.alamano
check PiHiXAozQpC66x.2.bel
check iNThQwz675mTJe.bel
check 4NCgLpD6CTbGNR.bel
#check HDXvXCsGLC5gmD.bel
check PiHiXAozQpC66x.bel
#check koeKWEd2iZ4Cf1.bel
check 5B8qhpV37DnECU.bel
check Hv1Dguu8CttXuS.bel
check RzN4SbevWyzTbH.bel
check ufdGXi69e5QFp5.bel

#run koeKWEd2iZ4Cf1.bel
