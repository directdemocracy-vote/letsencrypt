# letsencrypt renewal script

This is a Python script allowing the automatic renewal of the letsencrypt SSL certificate for the \*.directdemocracy.vote web sites.
It should be called from a crontab every month or so:
```
0	0	1	*	*	/home/account_folder/letsencrypt/letsencrypt.py
```

It uses the ACME v1 protocol which is going to be totally disabled in June 1st, 2021.
It should be upgraded to ACME v2 protocol using for example [AMCE-tiny](https://github.com/diafygi/acme-tiny).
