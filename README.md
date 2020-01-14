# How to run the server

In order to run the server you must have npm and the latest version of node installed:

```
sudo npm cache clean -f
sudo npm install -g n
sudo n 12.13.0
```

Run the following commands:

```
cd src/server/
npm i
npm run server
```

# How to run the client

```
cd src/client/
sudo apt-get install swig
sudo pip3 install -r requirements.txt
python3 client.py
```

# To hear all packets being sent to/from a process

```
sudo strace -p $PID -f -e trace=network -s 10000
```

Where $PID is the process that is running the client