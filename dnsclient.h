#ifndef DNSCLIENT_H
#define DNSCLIENT_H

#include <QObject>
#include <dnspacket.h>
#include <QUdpSocket>
#include <dnsservices.h>
#include <QTcpSocket>

class DNSCLIENT : public QObject
{
    Q_OBJECT
public:
    explicit DNSCLIENT(QObject *parent = 0);
    ~DNSCLIENT();
   bool nslookup(QString hostName, QString ServerIP = NULL);
   bool nslookup2(QString hostName, QString ServerIP = NULL);
   bool nslookup3 (QString hostName, QString ServerIP = NULL);

private:

   QUdpSocket udpSocket;
   void showAnswerInfo(DNS_ANSWER DA);
   void showQueryInfo(DNS_QUERY DQ);
   quint16 readAnswer (char*data,quint16 offset);

   quint16 readName (char *data, QByteArray *qName, quint16 offset);
   quint32 copyMem(char *dst, char* src, quint32 size);


   QByteArray changeToDNSNameFormat(QString hostName);

signals:

public slots:
};

#endif // DNSCLIENT_H
