echo "Welcome user"
echo "Starting the process by booting the NAC"
airmon-ng start wlan0

sleep 3s 
#wait for the program to boot up
echo "NAC booted"
python deauth.py -i wlan0mon
echo "Completed the information gathering"  
