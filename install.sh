 
#
#1 – Check sshd installation
#
sshd_path=$(which sshd)
if [ "$sshd_path" != "/usr/sbin/sshd" ]; then
	echo "Installing SSHD..."
	sudo apt-get install -y openssh-server
	sudo service sshd restart
	sudo reboot
fi

#
#2 – Configure Ubuntu
#
sudo apt-get update
sudo apt-get dist-upgrade

#
#1.1 – Configure Network
#
ens160=0
ens160_gro=$(cat /etc/network/interfaces | grep "post-up ethtool -K ens160 gro off")
if [ "$ens160_gro" == "post-up ethtool -K ens160 gro off" ]; then
  echo "'post-up ethtool -K ens160 gro off' set in inferfaces"
else
  sudo echo "post-up ethtool -K ens160 gro off" >> /etc/network/interfaces
  ens160=1
fi
ens160_lro=$(cat /etc/network/interfaces | grep "post-up ethtool -K ens160 lro off")
if [ "$ens160_lro" == "post-up ethtool -K ens160 lro off" ]; then
  echo "'post-up ethtool -K ens160 lro off' set in inferfaces"
else
  sudo echo "post-up ethtool -K ens160 lro off" >> /etc/network/interfaces
  ens160=1
fi

if [ $ens160 == 1 ]; then
  sudo /etc/init.d/networking restart
fi

#
#Restart the system and verify that LRO and GRO are disabled
#ethtool -k ens160 | grep receive-offload
#The output should look like this:
#generic-receive-offload: off
#large-receive-offload: of
#

#
#2 – Install Snort
#
 
#
#2.1 – Install Snort prerequisites
#
sudo apt-get install build-essential -y
 
sudo apt-get install libpcap-dev libpcre3-dev libdumbnet-dev -y

if [ ! -d "~/snort_src" ]; then
  mkdir ~/snort_src
fi

cd ~/snort_src/
sudo apt-get install bison flex -y
wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
tar -zxvf daq-2.0.6.tar.gz
cd daq-2.0.6/
./configure
make
sudo make install

sudo apt-get install zlib1g-dev liblzma-dev openssl libssl-dev -y

#
#And now let’s download, compile and install Snort:
#
cd ~/snort_src/
https://www.snort.org/downloads/archive/snort/snort-2.9.8.2.tar.gz
 tar -zxvf snort-2.9.8.2.tar.gz
./configure --enable-sourcefire
make
sudo make install

#Update the shared libraries, otherwise you will get an error when you try to run Snort:
sudo ldconfig

Create a symlink to the Snort binary:
sudo ln -s /usr/local/bin/snort /usr/sbin/snort

#
#Now run Snort as a normal user and verify the installation and the configuration:
#
snort -V 
#With the exception of the version numbers, the output should look similar to this:
# ,,_   -*> Snort! <*-
#o"  )~ Version 2.9.8.2 GRE (Build 335) 
# ''''  By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
#       Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
#       Copyright (C) 1998-2013 Sourcefire, Inc., et al.
#       Using libpcap version 1.7.4
#       Using PCRE version: 8.38 2015-11-23
#       Using ZLIB version: 1.2.8






