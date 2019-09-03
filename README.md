# letsencrypt renewal script

This is a Python script allowing the automatic renewal of the letsencrypt SSL certificate for the *.directdemocracy.vote web sites.
It should be called from a crontab every month or so:
```
0	0	1	*	*	/home/account_folder/letsencrypt/letsencrypt.py
```
