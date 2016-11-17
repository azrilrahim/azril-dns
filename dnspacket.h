#ifndef DNSPACKET

#define DNSPACKET

#include <QByteArray>
#include <QString>
#include <QtEndian>

/* based on my reading at http://www.tcpipguide.com/free/t_DNSMessageProcessingandGeneralMessageFormat.htm
 *
 * DNS Message format
 * ================================
 *
 * DNS_HEADER (12 bytes)
 * DNS_QUESTION
 * DNS_ANSWER
 * DNS_AUTHORITY
 * DNS_ADDITIONAL
 *
 */

struct DNS_HEADER_FLAGS{
    quint16 MSGID;         //16-bit identification field

    quint8 RD:1;        //This is 8 bit sequence in a byte
    quint8 TC:1;        //the arrangement is different from
    quint8 AA:1;        //documentation because it follows
    quint8 OPCDODE:4;   //the little endian scheme. even though
    quint8 QR:1;        //the is not such thing as endian bit arrangment: QR -> RD

    quint8 RCODE:4;     //another little endian arrangment for
    quint8 CD:1;
    quint8 AD:1;
    quint8 Z:1;         //for another byte
    quint8 RA: 1;       //RA -> RCODE

    quint16 QDCOUNT;
    quint16 ANCOUNT;
    quint16 NSCOUNT;
    quint16 ARCOUNT;
};

struct DNS_QUERY_FLAGS
{
    quint16 TYPE;
    quint16 CLASS;
};

struct DNS_LABEL_POINTER_FLAG{
    quint8 ABIT:1;
    quint8 BBIT:1;
};

struct DNS_ANSWER_FLAGS{
    quint16 TYPE;
    quint16 CLASS;
    quint32 TTL;
    quint16 RDLENGTH;
};

struct DNS_QUERY
{
    DNS_HEADER_FLAGS dnsHeaderFlags;
    QByteArray queryDomainName;
    DNS_QUERY_FLAGS dnsQueryFlags;
};

struct DNS_ANSWER
{
    DNS_HEADER_FLAGS dnsHeaderFlags;
    QByteArray queryDomainName;
    DNS_ANSWER_FLAGS dnsAnswerFlag;
    QByteArray rData;
};



#endif // DNSPACKET


