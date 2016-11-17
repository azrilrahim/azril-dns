#include "dnsclient.h"
#include <QHostAddress>

DNSCLIENT::DNSCLIENT(QObject *parent) : QObject(parent)
{

}

DNSCLIENT::~DNSCLIENT()
{

}


bool DNSCLIENT::
nslookup3(QString hostName, QString ServerIP)
{
    QByteArray opsData;
    QHostAddress sender;
    quint16 senderPort;
    quint16 offset;
    QUdpSocket myUDP;
    DNSSERVICES dsvcs;


    //create header
    DNS_HEADER_FLAGS DAF;
    DAF.MSGID = 1234;
    DAF.ANCOUNT = 0;
    DAF.ARCOUNT = 0;
    DAF.NSCOUNT = 0;
    DAF.QDCOUNT = 1;
    DAF.AA = 0;
    DAF.QR = 0;
    DAF.AD = 0;
    DAF.CD = 0;
    DAF.OPCDODE = 0;
    DAF.RA = 0;
    DAF.RCODE = 0;
    DAF.TC = 0;
    DAF.Z = 0;
    DAF.RD = 1;

    //create query
    opsData.clear();
    opsData.append(dsvcs.sWriteHeaderFlags(DAF));
    opsData.append(dsvcs.sWriteQueryName(hostName));
    opsData.append(dsvcs.sWriteQueryFlags());

    myUDP.connectToHost(ServerIP,53);
    if (!myUDP.waitForConnected())
    {
        qDebug() << "Unable to connect..";
        return false;
    }

    qDebug() << "Preparing data to server for" << opsData.size() << "bytes";
    qDebug() << "Writing data to server for" << myUDP.write(opsData) << "Bytes";
    qDebug() << "Waiting for reply";
    if (!myUDP.waitForReadyRead())
    {
        qDebug() << "Time out. Server not responding";
        return false;
    }

    opsData.clear();
    opsData.resize(myUDP.pendingDatagramSize());
    myUDP.readDatagram(opsData.data(),opsData.size(),&sender, &senderPort);
    //myUDP.abort();

    qDebug() << "Recieving reply for" << opsData.size() << "bytes";


    //read header
   DAF = dsvcs.sReadHeaderFlags(opsData.data(),&offset);
   if (DAF.RCODE != 0)
   {
       qDebug() << "Error on reply";
       return false;
   }

   //read query name
   dsvcs.sReadQueryName(opsData.data(),&offset);

   //read query flags
   dsvcs.sReadQueryFlags(opsData.data(), &offset);

   qDebug() << "There is" << DAF.ANCOUNT << "answers";

   //get the answer
   DNS_ANSWER_FLAGS DA;

   for (int ans = 0; ans < DAF.ANCOUNT; ans++)
   {
       qDebug() << "";
       qDebug() << "answer" << ans + 1;
       //read the query name
       qDebug() << "query name" << dsvcs.sReadQueryName(opsData.data(), &offset);
       DA = dsvcs.sReadAnswerFlags(opsData.data(), &offset);
       qDebug() << "result length is" << DA.RDLENGTH;
       qDebug() << "ip address:" << dsvcs.sReadRData(opsData.data(),&offset,DA.RDLENGTH);
   }

   return true;
}



bool DNSCLIENT::nslookup(QString hostName,QString ServerIP)
{

    QByteArray opsData;
    QHostAddress dd;
    QHostAddress sender;
    quint16 senderPort;
    quint16 offset;

    char *r;

    qDebug() << "Solving for" << hostName << "with" << ServerIP;
    if (!ServerIP.isNull())
        dd.setAddress(ServerIP);


    qDebug() << "Current name server" << dd.toString();
    opsData.clear();

    qDebug() << "Connecting...";
    this->udpSocket.connectToHost(ServerIP,53);
    if (!this->udpSocket.waitForConnected())
        return false;
    qDebug() << "Connected";

    //set the header
    DNS_QUERY DQ;

    qDebug() << "Forged Header";

    DQ.dnsHeaderFlags.MSGID = 5235;
    DQ.dnsHeaderFlags.MSGID = qFromBigEndian(DQ.dnsHeaderFlags.MSGID);
    DQ.dnsHeaderFlags.QR = 0;
    DQ.dnsHeaderFlags.OPCDODE = 0;
    DQ.dnsHeaderFlags.AA = 0;
    DQ.dnsHeaderFlags.TC = 0;
    DQ.dnsHeaderFlags.RD = 1;
    DQ.dnsHeaderFlags.RA = 0;
    DQ.dnsHeaderFlags.Z = 0;
    DQ.dnsHeaderFlags.AD = 0;
    DQ.dnsHeaderFlags.CD = 0;
    DQ.dnsHeaderFlags.RCODE = 0;
    DQ.dnsHeaderFlags.QDCOUNT = 1;
    DQ.dnsHeaderFlags.QDCOUNT = qFromBigEndian(DQ.dnsHeaderFlags.QDCOUNT);
    DQ.dnsHeaderFlags.ANCOUNT = 0;
    DQ.dnsHeaderFlags.NSCOUNT = 0;
    DQ.dnsHeaderFlags.ARCOUNT = 0;

    //append the flags into replyData
    r = (char*)&DQ.dnsHeaderFlags;
    opsData.append(r,sizeof(DQ.dnsHeaderFlags));

    qDebug() << "Forged HostName";
    //convert the hostname and append to query data;
    DQ.queryDomainName = changeToDNSNameFormat(hostName);
    opsData.append(DQ.queryDomainName);

    //set the query flags
    DQ.dnsQueryFlags.CLASS = 1;
    DQ.dnsQueryFlags.TYPE = 1;
    DQ.dnsQueryFlags.CLASS = qFromBigEndian(DQ.dnsQueryFlags.CLASS); //Its internet
    DQ.dnsQueryFlags.TYPE = qFromBigEndian(DQ.dnsQueryFlags.TYPE); //IPv4 address

    //append to the queryData
    r = (char*)&DQ.dnsQueryFlags;
    opsData.append(r,sizeof(DQ.dnsQueryFlags));

    this->showQueryInfo(DQ);

    //sent to dns server
    qDebug() << "Writing to NameServer for" << opsData.size() << "bytes";

    this->udpSocket.write(opsData);

    qDebug() << "Waiting for an answer";

    if (!this->udpSocket.waitForReadyRead())
        return false;

    qDebug() << "Incoming Answer";
    opsData.clear();
    opsData.resize(this->udpSocket.pendingDatagramSize());

    this->udpSocket.readDatagram(opsData.data(),opsData.size(),&sender,&senderPort);
    qDebug() << "processing" << opsData.size() << "bytes from:" << sender.toString() << ":" << senderPort;

    //get the answer header
    DNS_ANSWER DA;
    DNS_QUERY_FLAGS DQF;
    char *op = opsData.data();
    offset = 0;

    /*
     *  -----------------------
     *  + HEADER FLAGS        +
     *  -----------------------
     *  + Query Domain Name   +
     *  -----------------------
     *  + ANSWER FLAGS        +
     *  -----------------------
     */

    memcpy(&DA.dnsHeaderFlags,op,12);
    offset = 12;
    qDebug() << "Total answers:" << qToBigEndian(DA.dnsHeaderFlags.ANCOUNT);

    //read the query name
    QByteArray qname;

    qDebug() << "offset b4 name" << offset;
    offset = this->readName(op,&qname,offset);
    qDebug() << "offset after name" << offset;
    qDebug() << "Queried Name:" << qname;
    //read the query flags that comes together
    //qDebug() << "query flag size:" << sizeof(DQF);
    memcpy(&DQF,op + offset,4);

    qDebug() << "Query class" << qToBigEndian(DQF.CLASS);
    qDebug() << "Query Type" << qToBigEndian(DQF.TYPE);
    offset = offset + 4;

    quint16 ans = 0;
    qDebug() << "read answer";

    while(1)
    {
        if (ans >= qToBigEndian(DA.dnsHeaderFlags.ANCOUNT))
            break;

        qDebug() << "reading answer" << ans;
        offset = this->readName(op,&qname,offset);
        qDebug() << "Queried name:" << qname;
        offset = this->readAnswer(op,offset);
        ans++;
    }
    return true;




    //get the Query class
    DNS_QUERY_FLAGS DADQ;
    char *c = (char*)&DADQ;
    for (uint i=0; i < sizeof(DADQ); i++)
    {
        c[i] = op[offset];
        offset++;
    }




   for (int x=0; x < qToBigEndian(DA.dnsHeaderFlags.ANCOUNT); x++)
    {
        qDebug() << "Current Offset is:" << offset;
        offset = this->readAnswer(op,offset);
    }

    return true;
}

quint32 DNSCLIENT::copyMem(char *dst, char *src, quint32 size)
{
    quint32 loc;
    for (loc =0; loc < size; loc++)
    {
        dst[loc] = src[loc];
    }

    return loc;
}

quint16 DNSCLIENT::readName(char *data, QByteArray *qName, quint16 offset)
{

    qName->clear();


    quint16 pointerOffset;
    bool pointerFlag;
    pointerOffset = offset;

    qDebug() << "start" << QChar(data[offset]).unicode();
    pointerFlag = false;
    if (QChar(data[offset]).unicode() >=192)
    {
        //this is a pointer. get the location of the query name
        pointerOffset = QChar(data[offset + 1]).unicode();
        pointerFlag = true;
        offset = offset + 2;
        qDebug() << "its a pointer. reads start at" << pointerOffset;
    }
    else
    {
        qDebug() << "its a label";
    }

    //read the label;
    while(1)
    {
        if (data[pointerOffset] == 0)
        {
            qName->append(data[pointerOffset]);
            pointerOffset++;
            break;
        }
        qName->append(data[pointerOffset]);
        pointerOffset++;
    }

    if (!pointerFlag)
        return pointerOffset;
    else
        return offset;
}

quint16 DNSCLIENT::readAnswer(char *data, quint16 offset)
{
    DNS_ANSWER_FLAGS DAF;


    DAF.TTL = 0;
    DAF.CLASS = 0;
    DAF.RDLENGTH = 0;
    DAF.TYPE = 0;

    copyMem((char*)&DAF,data + offset,10);
    //qDebug() << "size of" << sizeof(quint16) << sizeof(quint32);
    //qDebug() << "size of DAF" << sizeof(struct DNS_ANSWER_FLAGS);
    //memcpy(&DAF,data + offset, 10);
    //read the query name
   // char *d = (char*)&DAF;
   // uint v;
   // for (v=0; v < sizeof(DAF); v++)
   // {
    //    d[v] = data[offset];
    //    offset++;
   // }

    offset = offset + 10;

    qDebug() << "Answer Info::ANSWER: TYPE:" << qToBigEndian(DAF.TYPE);
    qDebug() << "Answer Info::ANSWER: CLASS:" << qToBigEndian(DAF.CLASS);
    qDebug() << "Answer Info::ANSWER: TTL:" << qToBigEndian(DAF.TTL);
    qDebug() << "Answer Info::ANSWER: RDLENGTH:" << qToBigEndian(DAF.RDLENGTH);



    //for A record;
    quint32 AIP;
    AIP = 0;

   // d = (char*)&AIP;
    memcpy(&AIP,data + offset, qToBigEndian(DAF.RDLENGTH));
    offset = offset + qToBigEndian(DAF.RDLENGTH);//qToBigEndian(DAF.RDLENGTH);

    //for (v=0; v < qToBigEndian(DAF.RDLENGTH);v++)
    //{
    //    d[v] = data[offset];
    //    offset++;
    //}
    AIP = qToBigEndian(AIP);
    qDebug() << "Answer: IP address " << QHostAddress(AIP).toString();

    return offset;
}

void DNSCLIENT::showAnswerInfo(DNS_ANSWER DA)
{
    qDebug() << "Answer Info::Message Header: Message ID:" << qToBigEndian(DA.dnsHeaderFlags.MSGID);
    qDebug() << "Answer Info::Message Header: QR Code:" << DA.dnsHeaderFlags.QR;
    qDebug() << "Answer Info::Message Header: OPCODE:" << DA.dnsHeaderFlags.OPCDODE << "(0:QUERY 1:IQuery 2:STATUS)";
    qDebug() << "Answer Info::Message Header: AA AUTHORITIVE ANSWER:" << DA.dnsHeaderFlags.AA;
    qDebug() << "Answer Info::Message Header: TC TRUNCATION:" << DA.dnsHeaderFlags.TC;
    qDebug() << "Answer Info::Message Header: RD RECURS DESIRE?:" << DA.dnsHeaderFlags.RD;
    qDebug() << "Answer Info::Message Header: RA RECURS AVAILAB:" << DA.dnsHeaderFlags.RA;
    qDebug() << "Answer Info::Message Header: RCODE:" << DA.dnsHeaderFlags.RCODE;
    qDebug() << "Answer Info::Message Header: QDCOUNT NUMBER OF QUESTION ENTRIES?:" << qToBigEndian(DA.dnsHeaderFlags.QDCOUNT);
    qDebug() << "Answer Info::Message Header: ANCOUNT NUMBER OF ANSWER ENTRIES?:" << qToBigEndian(DA.dnsHeaderFlags.ANCOUNT);
    qDebug() << "Answer Info::Message Header: QDCOUNT NUMBER SERVER AUTHORITY ENTRIES?:" << qToBigEndian(DA.dnsHeaderFlags.NSCOUNT);
    qDebug() << "Answer Info::Message Header: QDCOUNT NUMBER RECORDS OF ADDITIONAL ENTRIES?:" << qToBigEndian(DA.dnsHeaderFlags.ARCOUNT);

    qDebug() << "Answer Info::Queried Domain Name:" << DA.queryDomainName;

    qDebug() << "Answer Info::ANSWER: TYPE:" << qToBigEndian(DA.dnsAnswerFlag.TYPE);
    qDebug() << "Answer Info::ANSWER: CLASS:" << qToBigEndian(DA.dnsAnswerFlag.CLASS);
    qDebug() << "Answer Info::ANSWER: TTL:" << qToBigEndian(DA.dnsAnswerFlag.TTL);
    qDebug() << "Answer Info::ANSWER: RDLENGTH:" << qToBigEndian(DA.dnsAnswerFlag.RDLENGTH);

    qDebug() << "Answer Info::ANSWER: RDATA:" << DA.rData;

}

void DNSCLIENT::showQueryInfo(DNS_QUERY DQ)
{
    qDebug() << "Query Info::Message Header: Message ID:" << qToBigEndian(DQ.dnsHeaderFlags.MSGID);
    qDebug() << "Query Info::Message Header: QR Code:" << DQ.dnsHeaderFlags.QR;
    qDebug() << "Query Info::Message Header: OPCODE:" << DQ.dnsHeaderFlags.OPCDODE << "(0:QUERY 1:IQuery 2:STATUS)";
    qDebug() << "Query Info::Message Header: AA AUTHORITIVE ANSWER:" << DQ.dnsHeaderFlags.AA;
    qDebug() << "Query Info::Message Header: TC TRUNCATION:" << DQ.dnsHeaderFlags.TC;
    qDebug() << "Query Info::Message Header: RD RECURS DESIRE?:" << DQ.dnsHeaderFlags.RD;
    qDebug() << "Query Info::Message Header: RA RECURS AVAILAB:" << DQ.dnsHeaderFlags.RA;
    qDebug() << "Query Info::Message Header: RCODE:" << DQ.dnsHeaderFlags.RCODE;
    qDebug() << "Query Info::Message Header: NUMBER OF QUESTION ENTRIES?:" << qToBigEndian(DQ.dnsHeaderFlags.QDCOUNT);
    qDebug() << "Query Info::Message Header: NUMBER OF ANSWER ENTRIES?:" << qToBigEndian(DQ.dnsHeaderFlags.ANCOUNT);
    qDebug() << "Query Info::Message Header: NUMBER SERVER AUTHORITY ENTRIES?:" << qToBigEndian(DQ.dnsHeaderFlags.NSCOUNT);
    qDebug() << "Query Info::Message Header: NUMBER RECORDS OF ADDITIONAL ENTRIES?:" << qToBigEndian(DQ.dnsHeaderFlags.ARCOUNT);

    qDebug() << "Query Info::Query: Domain Name:" << DQ.queryDomainName;
    qDebug() << "Query Info::Query: TYPE:" << qToBigEndian(DQ.dnsQueryFlags.TYPE);
    qDebug() << "Query Info::Query: CLASS:" << qToBigEndian(DQ.dnsQueryFlags.CLASS);
}

QByteArray DNSCLIENT::changeToDNSNameFormat(QString hostName)
{
    //this will convert e.g www.google.com to 3www6google3com
    QByteArray nName;
    QString tmp;
    int offset = 0;
    quint8 idc = 0;


    nName.clear();

    for (offset = 0; offset < hostName.size(); offset++)
    {
        if (hostName.at(offset) == '.')
        {
            nName.append(idc);
            nName.append(tmp);

            tmp.clear();
            idc = 0;
        }
        else
        {

            tmp.append(hostName.at(offset));
            idc++;
        }
    }

    nName.append(idc);
    nName.append(tmp);
    nName.append('\0');
    qDebug() << "Formated name is:" << nName;

    return nName;
}
