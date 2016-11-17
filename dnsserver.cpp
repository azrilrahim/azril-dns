#include "dnsserver.h"
#include <QDebug>

dnsserver::dnsserver(QObject *parent) : QObject(parent)
{
    connect(&this->udpSocket,SIGNAL(readyRead()),this,SLOT(onRequest()));
}

dnsserver::~dnsserver()
{

}

int dnsserver::startServer()
{
    return this->udpSocket.bind(53);
   //return this->udpSocket.bind(QHostAddress("127.0.0.1"),53,false?QUdpSocket::ReuseAddressHint:QUdpSocket::DefaultForPlatform);
}

QByteArray dnsserver::parseClientQuery(char *data)
{
    DNSSERVICES dsvcs;
    DNS_HEADER_FLAGS DHF;
    DNS_QUERY_FLAGS DQF;
    DNS_ANSWER_FLAGS DAF;

    quint32 hostIP;

    QString qName;
    quint16 offset;

    QByteArray answer;

    answer.clear();

    //read the header
    DHF = dsvcs.sReadHeaderFlags(data,&offset);

    qDebug() << "Query for" << DHF.QDCOUNT << "Domain(s)";
    qDebug() << "Message ID" << DHF.MSGID;

    //read the query name
    qName = dsvcs.sReadQueryName(data,&offset);
    qDebug() << "Query Name:" << qName;
    //read the query flags
    DQF = dsvcs.sReadQueryFlags(data, &offset);
    qDebug() << "Query Type" << DQF.TYPE;

    qDebug() << "\n";

    hostIP = QHostAddress("115.115.115.115").toIPv4Address();
    //qDebug() << "Making answer:" << QHostAddress(hostIP).toString();

    qDebug() << "Replying with answers";
    //make answer
    DHF.AA = 1;
    DHF.RD = 0;
    DHF.RA = 0;
    DHF.RCODE = 0;
    DHF.QR = 1; //response
    DHF.ANCOUNT = 1; // 1 answer;
    DHF.QDCOUNT = 1; // no question

    answer.append(dsvcs.sWriteHeaderFlags(DHF));
    answer.append(dsvcs.sWriteQueryName(qName));
    answer.append(dsvcs.sWriteQueryFlags(1,1));

    //answer part

    //query name label or pointer
    answer.append((dsvcs.sWriteQueryName(qName)));
    //answer flags
    DAF.TYPE = 1;
    DAF.CLASS = 1;
    DAF.TTL = 0;
    DAF.RDLENGTH = 4; //32 bits A records
    answer.append(dsvcs.sWriteAnswersFlags(DAF));

    //rdata
    answer.append(dsvcs.sWriteRData(hostIP));

    return answer;

}

void dnsserver::onRequest()
{
    //parse all the message from socket buffer
    while (this->udpSocket.hasPendingDatagrams()){

        QByteArray qDatagram;
        QByteArray aDatagram;

        qDatagram.resize(this->udpSocket.pendingDatagramSize());
        aDatagram.clear();

        QHostAddress sender;
        quint16 senderPort;

        this->udpSocket.readDatagram(qDatagram.data(),qDatagram.size(),&sender,&senderPort);


        qDebug() << "Incoming request from" << sender.toString() << ":" << senderPort << "for" << qDatagram.size() << "bytes";

        aDatagram = this->parseClientQuery(qDatagram.data());

        //aDatagram = this->dnsservice.parse(&qDatagram);



        if (aDatagram.size() > 0)
        {
           //reply it
            qDebug() << "Replying at" << aDatagram.size() << "bytes";
            this->udpSocket.writeDatagram(aDatagram,sender,senderPort);
        }
    }
}

