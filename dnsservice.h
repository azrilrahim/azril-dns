#ifndef DNSSERVICE_H
#define DNSSERVICE_H

#include <QByteArray>
#include <dnspacket.h>
#include <QString>
#include <QtEndian>
#include <QHostAddress>


class dnsservice
{
public:




    dnsservice();
    ~dnsservice();
    QByteArray parse(QByteArray *dataGram);

private:

    quint16 readNameFromReplyData(char *replyData, QByteArray aName, quint16 startOffset);
    DNS_QUERY processQuery(char *dataGram, quint16 dataSize);
    QByteArray processAnswer(DNS_QUERY dnsQuery);


    void showQueryInfo(DNS_QUERY DQ);
    void showAnswerInfo (DNS_ANSWER DA);

    QByteArray getQueryDomain(char *dataGram,quint16 offset,quint16 dataSize);
    bool processDNSFlags(char *dataGram);

   /* bool processQueryDomain(char *dataGram, quint16 dataSize);
    bool processQueryFlags(char *dataGram);


    QByteArray createARecordRDData();*/





    DNS_HEADER_FLAGS dnsFlags;
    QByteArray domainName;
    //DNS_QUESTION_FLAGS dnsQuestionFlags;

    //DNS_QUESTION_FLAG dnsQueryFlags;
    //DNS_ANSWER_FLAG dnsAnswerFlags;
    QByteArray queryDomainName;
    QByteArray rdData;
    quint16 dnsOpsOffset;

};

#endif // DNSSERVICE_H
