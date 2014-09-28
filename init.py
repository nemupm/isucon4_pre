# -*- coding:utf-8 -*-
import memcache
import MySQLdb
import json

print "start!"

#initialize memecached
memcachedclient = memcache.Client(['127.0.0.1:11211'])
memcachedclient.flush_all()

connector = MySQLdb.connect(
	host="127.0.0.1",
	db="isu4_qualifier",
	user="root",
	charset="utf8")
cursor = connector.cursor(MySQLdb.cursors.DictCursor)

sql = "select * from login_log ORDER BY created_at"
cursor.execute(sql)
login_log = cursor.fetchall()

banned_ips = []
locked_users = []
locked_users_login = []
users = {}
ips = {}
for row in login_log:
	user_id = row["user_id"]
	ip = row["ip"]
	if ip in banned_ips or user_id in locked_users:
		continue
	if row["succeeded"] == 1:
		if user_id not in users:
			users[user_id] = {
				"current_login_date": str(row["created_at"]),
				"last_login_date": None,
				"count_failed": 0,
				"current_ip": ip,
				"last_ip": None
			}
		else:
			users[user_id] = {
				"current_login_date": str(row["created_at"]),
				"last_login_date": users[user_id]["current_login_date"],
				"count_failed": 0,
				"current_ip": ip,
				"last_ip": users[user_id]["current_ip"]
			}
		ips[ip] = {"count_failed": 0}
	else:
		if user_id not in users:
			users[user_id] = {
				"current_login_date": None,
				"last_login_date": None,
				"count_failed": 1,
				"current_ip": None,
				"last_ip": None
			}
		else:
			users[user_id]["count_failed"] += 1
			ips.setdefault(ip,{"count_failed":0})
			ips[ip]["count_failed"] += 1
			if users[user_id]["count_failed"] == 3:
				locked_users.append(user_id)
				del users[user_id]
			if ips[ip]["count_failed"] == 10:
				banned_ips.append(ip)
				del ips[ip]

sql = "select * from users"
cursor.execute(sql)
user_data = cursor.fetchall()
for i,user in enumerate(user_data):
	user_id = user["id"]
	login = user["login"]
	if user_id in users:
		memcachedclient.set(
			"id_%s" % login.encode('utf-8'),
			json.dumps({
				"current_login_date": users[user_id]["current_login_date"],
				"last_login_date": users[user_id]["last_login_date"],
				"count_failed": users[user_id]["count_failed"],
				"current_ip": users[user_id]["current_ip"],
				"last_ip": users[user_id]["last_ip"],
				"password_hash": user["password_hash"],
				"salt": user["salt"]
			})
		)
	else:
		if user_id in locked_users:
			locked_users_login.append(login)
		else:
			memcachedclient.set(
				"id_%s" % login.encode('utf-8'),
				json.dumps({
					"current_login_date": None,
					"last_login_date": None,
					"count_failed": 0,
					"current_ip": None,
					"last_ip": None,
					"password_hash": user["password_hash"],
					"salt": user["salt"]
				})
			)
	if i % 10000 == 0:
		print i
for ip,v in ips.items():
	memcachedclient.set(
			str("ip_%s" % ip),
			json.dumps({
				"count_failed": v["count_failed"]
			})
		)
memcachedclient.set("locked_users",json.dumps({"list":locked_users_login}))
memcachedclient.set("banned_ips",json.dumps({"list":banned_ips}))

cursor.close()
connector.close()

print "finish!"

