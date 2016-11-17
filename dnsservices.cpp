#include "dnsservices.h"

DNSSERVICES::DNSSERVICES()
{

}

DNSSERVICES::~DNSSERVICES()
{

}


QByteArray DNSSERVICES::sWriteHeaderFlags(DNS_HEADER_FLAGS DH)
{
    char *r;
    QByteArray data;

    data.clear();

    //convert from qBigEndian
    DH.MSGID = qFromBigEndian(DH.MSGID);
    DH.ANCOUNT = qFromBigEndian(DH.ANCOUNT);
    DH.ARCOUNT = qFromBigEndian(DH.ARCOUNT);
    DH.NSCOUNT = qFromBigEndian(DH.NSCOUNT);
    DH.QDCOUNT = qFromBigEndian(DH.QDCOUNT);
    r = (char*)&DH;
    data.append(r,12);
    return data;
}

DNS_HEADER_FLAGS DNSSERVICES::sReadHeaderFlags(char *data, quint16 *offset)
{

    DNS_HEADER_FLAGS DHF;

    memcpy(&DHF,data,12);
    *offset = 12;

    DHF.MSGID = qToBigEndian(DHF.MSGID);
    DHF.ANCOUNT = qToBigEndian(DHF.ANCOUNT);
    DHF.ARCOUNT = qToBigEndian(DHF.ARCOUNT);
    DHF.NSCOUNT = qToBigEndian(DHF.NSCOUNT);
    DHF.QDCOUNT = qToBigEndian(DHF.QDCOUNT);
    return DHF;
}

QByteArray DNSSERVICES::sWriteQueryName(QString queryName)
{
    //this will convert e.g www.google.com to 3www6google3com
    QByteArray nName;
    QString tmp;
    int offset = 0;
    quint8 idc = 0;

    QStringList ls;

    //qDebug() << "Input name is:" << hostName;
    ls = queryName.trimmed().split(".");
    nName.clear();


    for (offset = 0; offset < ls.size(); offset++)
    {
        //qDebug() << "ls:" << offset + 1 << ls.at(offset) << "  size:" << ls.at(offset).size();
        nName.append(ls.at(offset).size());
        //qDebug() << ":=" << nName;
        nName.append(ls.at(offset));
        //qDebug() << ":=" << nName;
    }

    nName.append('\0');
    qDebug() << "Formatted name isX:" << nName;
    return nName;


    for (offset = 0; offset < queryName.size(); offset++)
    {
        if (queryName.at(offset) == '.')
        {
            nName.append(idc);
            nName.append(tmp);

            tmp.clear();
            idc = 0;
        }
        else
        {

            tmp.append(queryName.at(offset));
            idc++;
        }
    }

    nName.append(idc);
    nName.append(tmp);
    nName.append('\0');
    //qDebug() << "Formated name is:" << nName;

    return nName;
}

QString DNSSERVICES::sReadQueryName(char *data, quint16 *offset)
{
    /*
     * read the queried name from the reply data produced from the corresponding DNS server.
     * This function will read the label as well the pointer
     */
    quint16 pointerOffset;
    bool pointerFlag;
    QString aName;
    pointerOffset = *offset;
    QChar h;

    bool skipFirst = true;

    //clear the queried name
    aName.clear();
    pointerFlag = false;


    //check if we are reading a label or pointer at the starting offset
    if (QChar(data[*offset]).unicode() >=192)
    {
        qDebug() << "reading pointer";
        //this is a pointer. get the location of the query name
        pointerOffset = QChar(data[*offset + 1]).unicode();
        pointerFlag = true;
        //if it is a pointer.. we need to move the offset by 2 bytes.
        //this will skipped the 16bits pointer address and set the new
        //reading offset to DNS ANSWER TYPE field.
        *offset = *offset + 2;
    }
    else
    {
        qDebug() << "Reading a Label";
    }

    //read the label;
    while(1)
    {
        h = data[pointerOffset];
        if (h.isLetterOrNumber())
            aName.append(h);
        else
        {
            if (h.isNull())
            {
                //aName.append(h);
                break;
            }
            if (!skipFirst)
                aName.append(".");
            else
                skipFirst = false;
        }
        pointerOffset++;
    }

    if (!pointerFlag)
        *offset = pointerOffset;

    return aName;
}

QByteArray DNSSERVICES::sWriteQueryFlags(quint16 qType, quint16 qClass)
{
    DNS_QUERY_FLAGS DQF;
    QByteArray data;
    char *r;

    data.clear();

    //write the flag
    DQF.CLASS = qClass;
    DQF.TYPE = qType;
    DQF.CLASS = qFromBigEndian(DQF.CLASS);
    DQF.TYPE = qFromBigEndian(DQF.TYPE);

    r = (char*)&DQF;
    data.append(r,4);
    return data;
}

DNS_QUERY_FLAGS DNSSERVICES::sReadQueryFlags(char *data, quint16 *offset)
{
    DNS_QUERY_FLAGS DQF;

    memcpy(&DQF,data + *offset,4);
    *offset = *offset + 4;

    DQF.CLASS = qToBigEndian(DQF.CLASS);
    DQF.TYPE = qToBigEndian(DQF.TYPE);

    return DQF;
}

QByteArray DNSSERVICES::sWriteAnswersFlags(DNS_ANSWER_FLAGS DAF)
{
    char *r;
    QByteArray outd;

    outd.clear();

    DAF.TYPE = qFromBigEndian(DAF.TYPE);
    DAF.CLASS = qFromBigEndian(DAF.CLASS);
    DAF.TTL = qFromBigEndian(DAF.TTL);
    DAF.RDLENGTH = qFromBigEndian(DAF.RDLENGTH);

    r = (char*)&DAF;
    outd.append(r,10);
    return outd;
}

DNS_ANSWER_FLAGS DNSSERVICES::sReadAnswerFlags(char *data, quint16 *offset)
{
    DNS_ANSWER_FLAGS DAF;
    memcpy(&DAF,data + *offset,10);
    *offset = *offset + 10;

    DAF.CLASS = qToBigEndian(DAF.CLASS);
    DAF.RDLENGTH = qToBigEndian(DAF.RDLENGTH);
    DAF.TTL = qToBigEndian(DAF.TTL);
    DAF.TYPE = qToBigEndian(DAF.TYPE);

    return DAF;
}

QByteArray DNSSERVICES::sWriteRData(void *data, quint16 size)
{
    QByteArray outd;
    outd.clear();
    outd.append((char*)data,size);
    return outd;
}

QByteArray DNSSERVICES::sWriteRData(quint32 data)
{
    char *r;
    QByteArray outd;
    data = qFromBigEndian(data);

    outd.clear();
    r= (char*)&data;

    outd.append(r,4);
    return outd;
}

QByteArray DNSSERVICES::sReadRData(char *data, quint16 *offset, quint16 size)
{
    QByteArray outdata;

    outdata.clear();
    outdata.append(data + *offset,size);

    *offset = *offset + size;
    return outdata;
}




QByteArray DNSSERVICES::changeToDNSNameFormat(QString hostName)
{
    //this will convert e.g www.google.com to 3www6google3com
    QByteArray nName;
    QString tmp;
    int offset = 0;
    quint8 idc = 0;

    QStringList ls;

    //qDebug() << "Input name is:" << hostName;
    ls = hostName.split(".");
    nName.clear();


    for (offset = 0; offset < ls.size(); offset++)
    {
        //qDebug() << "ls:" << offset + 1 << ls.at(offset) << "  size:" << ls.at(offset).size();
        nName.append(ls.at(offset).size());
        //qDebug() << ":=" << nName;
        nName.append(ls.at(offset));
        //qDebug() << ":=" << nName;
    }

    nName.append('\0');
    //qDebug() << "Formatted name is:" << nName;
    return nName;


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



