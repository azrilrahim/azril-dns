#include "dnsservice.h"
#include <QDebug>

dnsservice::dnsservice()
{

}

dnsservice::~dnsservice()
{

}
QByteArray dnsservice::parse(QByteArray *dataGram)
{

    /*basic process for dns
     * 1. get question header
     * 2. get question name
     * 3. reply answer
     */
    QByteArray reply;
    reply.clear();

    DNS_QUERY DQ = processQuery(dataGram->data(),dataGram->size());
    if (DQ.queryDomainName.isEmpty())
        return reply;

    this->showQueryInfo(DQ);


    //create answer
    reply = this->processAnswer(DQ);

    return reply;
}

DNS_QUERY dnsservice::processQuery(char *dataGram,quint16 dataSize)
{
    /*
     * incoming query comes with 3 sections
     * DNS HEADER FLAGS
     * Query Domain Name
     * DNS Query Flags
     */

    quint16 offset;
    DNS_QUERY DQ;

    DQ.queryDomainName.clear();


    //get the header
    memcpy(&DQ.dnsHeaderFlags,dataGram,sizeof(DQ.dnsHeaderFlags));
    offset = sizeof(DQ.dnsHeaderFlags);

    //we only process Query
    if (DQ.dnsHeaderFlags.QR != 0x00) //not a query
        return DQ;

    //its a query.. get the query domain name;
    DQ.queryDomainName = this->getQueryDomain(dataGram,offset,dataSize);
    if (DQ.queryDomainName.size() == 0)
        return DQ;
    offset = offset + DQ.queryDomainName.size() + 1;

    //get the query flag
    memcpy(&DQ.dnsQueryFlags,dataGram + offset,sizeof(DQ.dnsQueryFlags));
    offset = offset + sizeof(DQ.dnsQueryFlags);


    return DQ;
}

QByteArray dnsservice::processAnswer(DNS_QUERY dnsQuery)
{
    DNS_ANSWER dnsAnswer;
    quint32 ARecord;

    QByteArray replyData;
    replyData.clear();


    //copy the dns query header to dns answer header and change response code
    dnsAnswer.dnsHeaderFlags = dnsQuery.dnsHeaderFlags;
    dnsAnswer.dnsHeaderFlags.QR = 0x1;

    qDebug() << "Query:" << dnsQuery.dnsHeaderFlags.QR;
    qDebug() << "Answer:" << dnsAnswer.dnsHeaderFlags.QR;

    dnsAnswer.queryDomainName = dnsQuery.queryDomainName;

    dnsAnswer.dnsAnswerFlag.TYPE = 1;
    qDebug() << "==========================" << dnsAnswer.dnsAnswerFlag.TYPE;
    dnsAnswer.dnsAnswerFlag.TYPE = qFromBigEndian(dnsAnswer.dnsAnswerFlag.TYPE);
     qDebug() << "==========================" << dnsAnswer.dnsAnswerFlag.TYPE;

    dnsAnswer.dnsAnswerFlag.CLASS = 1;
    dnsAnswer.dnsAnswerFlag.CLASS = qFromBigEndian(dnsAnswer.dnsAnswerFlag.CLASS);

    dnsAnswer.dnsAnswerFlag.TTL = 0;

    //convert ip address to long
    ARecord = QHostAddress("128.128.128.44").toIPv4Address();
    dnsAnswer.dnsAnswerFlag.RDLENGTH = 4;
    dnsAnswer.dnsAnswerFlag.RDLENGTH = qFromBigEndian(dnsAnswer.dnsAnswerFlag.RDLENGTH);

    ARecord = qToLittleEndian(ARecord);
    char *c = (char*)&ARecord;
    dnsAnswer.rData.clear();
    dnsAnswer.rData.append(c,sizeof(ARecord));

    this->showAnswerInfo(dnsAnswer);


    //copy all data in the DNS_ANSWER INTO replyData;

    //append the DNS Header flag
    c = (char*)&dnsAnswer.dnsHeaderFlags;
    replyData.append(c,sizeof(dnsAnswer.dnsHeaderFlags));
    qDebug() << "append data is"  << sizeof(dnsAnswer.dnsHeaderFlags);

    //append the query domain name
    replyData.append(dnsAnswer.queryDomainName);
    qDebug() << "append data is"  << dnsAnswer.queryDomainName.size();
    qDebug() << "Domain name:" << dnsAnswer.queryDomainName;

    //append the answer flag
    c = (char*)&dnsAnswer.dnsAnswerFlag;
    replyData.append(c,sizeof(dnsAnswer.dnsAnswerFlag));
    qDebug() << "append data is"  << sizeof(dnsAnswer.dnsAnswerFlag);

    //append the rdata
    replyData.append(dnsAnswer.rData);
    qDebug() << "append data is"  << dnsAnswer.rData.size();

    qDebug() << "reply data size is" << replyData.size();
    return replyData;

}

void dnsservice::showQueryInfo(DNS_QUERY DQ)
{
    qDebug() << "Query Info::Message Header: Message ID:" << qToBigEndian(DQ.dnsHeaderFlags.MSGID);
    qDebug() << "Query Info::Message Header: QR Code:" << DQ.dnsHeaderFlags.QR;
    qDebug() << "Query Info::Message Header: OPCODE:" << DQ.dnsHeaderFlags.OPCDODE << "(0:QUERY 1:IQuery 2:STATUS)";
    qDebug() << "Query Info::Message Header: AA AUTHORITIVE ANSWER:" << DQ.dnsHeaderFlags.AA;
    qDebug() << "Query Info::Message Header: TC TRUNCATION:" << DQ.dnsHeaderFlags.TC;
    qDebug() << "Query Info::Message Header: RD RECURS DESIRE?:" << DQ.dnsHeaderFlags.RD;
    qDebug() << "Query Info::Message Header: RA RECURS AVAILAB:" << DQ.dnsHeaderFlags.RA;
    qDebug() << "Query Info::Message Header: RCODE:" << DQ.dnsHeaderFlags.RCODE;
    qDebug() << "Query Info::Message Header: QDCOUNT NUMBER OF QUESTION ENTRIES?:" << qToBigEndian(DQ.dnsHeaderFlags.QDCOUNT);
    qDebug() << "Query Info::Message Header: ANCOUNT NUMBER OF ANSWER ENTRIES?:" << qToBigEndian(DQ.dnsHeaderFlags.ANCOUNT);
    qDebug() << "Query Info::Message Header: QDCOUNT NUMBER SERVER AUTHORITY ENTRIES?:" << qToBigEndian(DQ.dnsHeaderFlags.NSCOUNT);
    qDebug() << "Query Info::Message Header: QDCOUNT NUMBER RECORDS OF ADDITIONAL ENTRIES?:" << qToBigEndian(DQ.dnsHeaderFlags.ARCOUNT);

    qDebug() << "Query Info::Query: Domain Name:" << DQ.queryDomainName;
    qDebug() << "Query Info::Query: TYPE:" << qToBigEndian(DQ.dnsQueryFlags.TYPE);
    qDebug() << "Query Info::Query: CLASS:" << qToBigEndian(DQ.dnsQueryFlags.CLASS);
}

void dnsservice::showAnswerInfo(DNS_ANSWER DA)
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

QByteArray dnsservice::getQueryDomain(char *dataGram, quint16 offset, quint16 dataSize)
{
    QByteArray rs;
    quint16 tloc = offset;
    rs.clear();
    while(1)
    {
        if (tloc >= dataSize)
        {
            rs.clear();
            return rs;
        }

        if (dataGram[tloc] == 0x00)
        {
            //null pointer. end of string
            break;
        }

        //add into the data byte
        rs.append(dataGram[tloc]);
        tloc++;
    }
    return rs;
}





