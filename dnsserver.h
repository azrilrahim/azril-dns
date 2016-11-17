#ifndef DNSSERVER_H
#define DNSSERVER_H

#include <QObject>
#include <QUdpSocket>
#include <dnsservice.h>
#include <dnsservices.h>

class dnsserver : public QObject
{
    Q_OBJECT
public:
    explicit dnsserver(QObject *parent = 0);
    ~dnsserver();
    int startServer();

private:

    QByteArray parseClientQuery(char *data);


    QUdpSocket udpSocket;
    dnsservice dnsservice;


signals:

public slots:
    void onRequest(); //processing any DNS Request Message
};

#endif // DNSSERVER_H
