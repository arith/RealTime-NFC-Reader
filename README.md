Two program exists for this simple demo:

1) NFC explore daemon

Requirements:

	1) wiringPi  : installed by default on raspbian
	2) libjason
		* git clone https://github.com/json-c/json-c.git
		* cd json-c
		* ./autogen.sh
		* ./configure
		* make
		* sudo make install
		* sudo nano /etc/ld.so.conf
			add the following line: /etc/local/lib
			ctrl+x to exit
		* sudo ldconfig

Build from source:

    1) cd to "*/nfc/build" directory
	2) cmake ../source
	3) make
	4) sudo ./nfc

2) NFC web server running on node.js

Requirements:

    1) Node.js : wget http://node-arm.herokuapp.com/node_latest_armhf.deb && sudo dpkg -i node_latest_armhf.deb
    2) cd to "*/nfc/server" directory
    3) sudo npm install

Running web server

    1) cd to "*/nfc/server"
    2) sudo node nfcserver.js

That's it.

To test:

    1) Open web browser and go to "http:<raspberrypi_ip_address>:3000"

Run at boot (assuming nfc binary is installed in "/usr/bin" and nfcserver.js and etc. is in "~/nfc/server":

On terminal:

1) sudo nano /etc/init/rc.local

        #!/bin/sh -e
        #rc.local
        
        # This script is executed at the end of each multiuser runlevel.
        # Make sure that the script will "exit 0" on success or any other
        # value on error.
        #
        # In order to enable or disable this script just change the execution
        # bits.
        #
        # By default this script does nothing.

        # Print the IP address
        _IP=$(hostname -I) || true
        if [ "$_IP" ]; then
          printf "My IP address is %s\n" "$_IP"
        fi

        #Autorun
        sudo nfc &
        su pi -c 'sudo node ~/nfc/server/nfcserver.js < /dev/null  &'
        exit 0


exit and reboot pi!

Regards.	

