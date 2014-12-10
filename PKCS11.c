#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include "PKCS11.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>

#include <unistd.h>
//#include <stdbool.h>


CK_BBOOL Debug = FALSE;

//pipe na komunikaciu s PKCS implementaciou
char* pkcs11fifo_read_path = "/tmp/pkcs11fifo1";
char* pkcs11fifo_write_path = "/tmp/pkcs11fifo2";
int pkcs11fifo_read_desc;
int pkcs11fifo_write_desc;
int MAX_PKSC11FIFO_BUF = 4096;

//zapamatany template z FindObjectsInit
CK_ATTRIBUTE_PTR zapamatanyTemplate;
CK_ULONG zapamatanyTemplateCount;

void dajSpravuZPipe(char sprava[]) {
    pkcs11fifo_read_desc = open(pkcs11fifo_read_path, O_RDONLY);
    read(pkcs11fifo_read_desc, sprava, MAX_PKSC11FIFO_BUF);
    close(pkcs11fifo_read_desc);
}

void napisDoPipe(char * sprava) {
    strcat(sprava, "\0");
    pkcs11fifo_write_desc = open(pkcs11fifo_write_path, O_WRONLY);    
    write(pkcs11fifo_write_desc, sprava, strlen(sprava));
    close(pkcs11fifo_write_desc);
}

void posliSpravuJave(char * sprava) {   
    napisDoPipe(sprava);   
}

void dajSpravuZJavy(char sprava[]) {   
    dajSpravuZPipe(sprava);    
}












/// <summary>
/// if 'Debug' is set to TRUE, this function writes a record to file 'C:\wmpkcs11.txt'. This record contains the current date and time and the string from the provided buffer.
/// </summary>
/// <param name="pStr">Char buffer to write with the record.</param>

/**
 * Funkcia logne do konzoly retazec znakov
 * @param pStr - retazec znakov, ktory sa ma zalogovat do konzoly
 */
void ConsoleLog(char* pStr) {
    printf("%s\n", pStr);
}

void ConsoleLogUnsignedLongInt(unsigned long int cislo) {
    printf("%lu\n", cislo);
}

/**
 * Poskytne zoznam funkcii, ktore tento modul poskytuje
 * @param ppFunctionList - zoznam, do ktoreho sa naplnia poskytovane funkcie
 * @return - zoznam funkcii
 */
CK_RV CK_ENTRY C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {            
    ConsoleLog("C_GetFunctionList entered");   

    //ziskame si prvotnu init spravu z javy
    char spravaZJavy[MAX_PKSC11FIFO_BUF];
    dajSpravuZJavy(spravaZJavy);
    printf("SPRAVA Z JAVY: %s", spravaZJavy);  
    
    if (ppFunctionList == NULL) {
        ConsoleLog("C_GetFunctionList failed: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }

    //vytvorim si zoznam funkcii
    *ppFunctionList = (CK_FUNCTION_LIST*) malloc(sizeof (CK_FUNCTION_LIST));
    (*ppFunctionList)->version.major = 2;
    (*ppFunctionList)->version.minor = 30;

    (*ppFunctionList)->C_Initialize = C_Initialize;
    (*ppFunctionList)->C_Finalize = C_Finalize;
    (*ppFunctionList)->C_GetInfo = C_GetInfo;
    (*ppFunctionList)->C_GetFunctionList = C_GetFunctionList;
    (*ppFunctionList)->C_GetSlotList = C_GetSlotList;
    (*ppFunctionList)->C_GetSlotInfo = C_GetSlotInfo;
    (*ppFunctionList)->C_GetTokenInfo = C_GetTokenInfo;
    (*ppFunctionList)->C_GetMechanismList = C_GetMechanismList;
    (*ppFunctionList)->C_GetMechanismInfo = C_GetMechanismInfo;
    (*ppFunctionList)->C_InitToken = C_InitToken;
    (*ppFunctionList)->C_OpenSession = C_OpenSession;
    (*ppFunctionList)->C_CloseSession = C_CloseSession;
    (*ppFunctionList)->C_CloseAllSessions = C_CloseAllSessions;
    (*ppFunctionList)->C_GetSessionInfo = C_GetSessionInfo;
    (*ppFunctionList)->C_Login = C_Login;
    (*ppFunctionList)->C_Logout = C_Logout;
    (*ppFunctionList)->C_InitPIN = C_InitPIN;
    (*ppFunctionList)->C_SetPIN = C_SetPIN;
    (*ppFunctionList)->C_GetOperationState = C_GetOperationState;
    (*ppFunctionList)->C_SetOperationState = C_SetOperationState;
    (*ppFunctionList)->C_GetFunctionStatus = C_GetFunctionStatus;
    (*ppFunctionList)->C_CancelFunction = C_CancelFunction;
    (*ppFunctionList)->C_CreateObject = C_CreateObject;
    (*ppFunctionList)->C_CopyObject = C_CopyObject;
    (*ppFunctionList)->C_DestroyObject = C_DestroyObject;
    (*ppFunctionList)->C_GetObjectSize = C_GetObjectSize;
    (*ppFunctionList)->C_GetAttributeValue = C_GetAttributeValue;
    (*ppFunctionList)->C_SetAttributeValue = C_SetAttributeValue;
    (*ppFunctionList)->C_FindObjectsInit = C_FindObjectsInit;
    (*ppFunctionList)->C_FindObjects = C_FindObjects;
    (*ppFunctionList)->C_FindObjectsFinal = C_FindObjectsFinal;
    (*ppFunctionList)->C_EncryptInit = C_EncryptInit;
    (*ppFunctionList)->C_Encrypt = C_Encrypt;
    (*ppFunctionList)->C_EncryptUpdate = C_EncryptUpdate;
    (*ppFunctionList)->C_EncryptFinal = C_EncryptFinal;
    (*ppFunctionList)->C_DecryptInit = C_DecryptInit;
    (*ppFunctionList)->C_Decrypt = C_Decrypt;
    (*ppFunctionList)->C_DecryptUpdate = C_DecryptUpdate;
    (*ppFunctionList)->C_DecryptFinal = C_DecryptFinal;
    (*ppFunctionList)->C_DigestInit = C_DigestInit;
    (*ppFunctionList)->C_Digest = C_Digest;
    (*ppFunctionList)->C_DigestUpdate = C_DigestUpdate;
    (*ppFunctionList)->C_DigestKey = C_DigestKey;
    (*ppFunctionList)->C_DigestFinal = C_DigestFinal;
    (*ppFunctionList)->C_SignInit = C_SignInit;
    (*ppFunctionList)->C_Sign = C_Sign;
    (*ppFunctionList)->C_SignUpdate = C_SignUpdate;
    (*ppFunctionList)->C_SignFinal = C_SignFinal;
    (*ppFunctionList)->C_SignRecoverInit = C_SignRecoverInit;
    (*ppFunctionList)->C_SignRecover = C_SignRecover;
    (*ppFunctionList)->C_VerifyInit = C_VerifyInit;
    (*ppFunctionList)->C_Verify = C_Verify;
    (*ppFunctionList)->C_VerifyUpdate = C_VerifyUpdate;
    (*ppFunctionList)->C_VerifyFinal = C_VerifyFinal;
    (*ppFunctionList)->C_VerifyRecoverInit = C_VerifyRecoverInit;
    (*ppFunctionList)->C_VerifyRecover = C_VerifyRecover;
    (*ppFunctionList)->C_DigestEncryptUpdate = C_DigestEncryptUpdate;
    (*ppFunctionList)->C_DecryptDigestUpdate = C_DecryptDigestUpdate;
    (*ppFunctionList)->C_SignEncryptUpdate = C_SignEncryptUpdate;
    (*ppFunctionList)->C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
    (*ppFunctionList)->C_GenerateKey = C_GenerateKey;
    (*ppFunctionList)->C_GenerateKeyPair = C_GenerateKeyPair;
    (*ppFunctionList)->C_WrapKey = C_WrapKey;
    (*ppFunctionList)->C_UnwrapKey = C_UnwrapKey;
    (*ppFunctionList)->C_DeriveKey = C_DeriveKey;
    (*ppFunctionList)->C_SeedRandom = C_SeedRandom;
    (*ppFunctionList)->C_GenerateRandom = C_GenerateRandom;
    (*ppFunctionList)->C_WaitForSlotEvent = C_WaitForSlotEvent;

    ConsoleLog("C_GetFunctionList succeeded");
    return CKR_OK;
}

/**
 * Inicializacia, zavola sa na zaciatku (po spusteni prehliadaca)
 * @param pInitArgs
 * @return 
 */
CK_RV CK_ENTRY C_Initialize(CK_VOID_PTR pInitArgs) {
    ConsoleLog("C_Initialize entered");
 
    if (pInitArgs != NULL_PTR) {

        if (((CK_C_INITIALIZE_ARGS_PTR) pInitArgs)->pReserved != NULL_PTR) {
            ConsoleLog("C_Initialize failed: CKR_ARGUMENTS_BAD");
            return CKR_ARGUMENTS_BAD;
        }
        if ((((CK_C_INITIALIZE_ARGS_PTR) pInitArgs)->CreateMutex != NULL_PTR) || (((CK_C_INITIALIZE_ARGS_PTR) pInitArgs)->DestroyMutex != NULL_PTR) || (((CK_C_INITIALIZE_ARGS_PTR) pInitArgs)->LockMutex != NULL_PTR) || (((CK_C_INITIALIZE_ARGS_PTR) pInitArgs)->UnlockMutex != NULL_PTR) || (((CK_C_INITIALIZE_ARGS_PTR) pInitArgs)->flags != 0)) { // we do not support multithreaded access
            ConsoleLog("C_Initialize failed: CKR_CANT_LOCK");
            return CKR_CANT_LOCK;
        }
    } else {

    }

    return CKR_OK;
}

/**
 * Zavola sa po dokonceni (pri zatvarani prehliadaca)
 * @param pReserved
 * @return 
 */
CK_RV CK_ENTRY C_Finalize(CK_VOID_PTR pReserved) {
    ConsoleLog("C_Finalize entered");

    return CKR_OK;
}

/**
 * Poskytne zakladne informacie o module
 * @param pInfo - sem sa naplnia informacie o module
 * @return 
 */
CK_RV CK_ENTRY C_GetInfo(CK_INFO_PTR pInfo) {
    ConsoleLog("C_GetInfo entered");

    //osetrenie zleho parametra
    if (pInfo == NULL) {
        ConsoleLog("C_GetInfo failed: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }



    strcpy(pInfo->manufacturerID, " Matej Kurpel ");
    pInfo->flags = 0;
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 11;
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    strcpy(pInfo->libraryDescription, " WMPKCS#11 - WinMobile module ");

    return CKR_OK;
}

/**
 * Poskytne zoznam vsetkych slotov
 * @param tokenPresent - TRUE znamena, ze ziskavame iba sloty s tokenmi, FALSE znamena, ze ziskavame vsetky sloty
 * @param pSlotList - ak je NULL_PTR, ziskavame pocet slotov, inak aj zoznam slotov
 * @param pulCount - sem sa naplni pocet slotov
 * @return 
 */
CK_RV CK_ENTRY C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    ConsoleLog("C_GetSlotList entered");    
    
    if (pSlotList == NULL_PTR) { //ziskavame pocet slotov (1)
        if (tokenPresent == TRUE) { //only slots with present tokens            
            *pulCount = 1;
        } else { //all slots            
            *pulCount = 1;
        }

    } else { //ziskavame zoznam slotov (2)
        if (tokenPresent == TRUE) { //vsetky sloty            
        } else { //sloty s dostupnymi tokenmi            
            pSlotList[0] = 123;
            *pulCount = 1;
        }
    }    
    
    return CKR_OK;
}

/**
 * Poskytne informacie o danom slote
 * @param SlotId - identifikator slotu
 * @param pInfo - sem sa naplnia informacie o slote
 * @return 
 */
CK_RV CK_ENTRY C_GetSlotInfo(CK_SLOT_ID SlotId, CK_SLOT_INFO_PTR pInfo) {
    ConsoleLog("C_GetSlotInfo entered");

    strcpy(pInfo->slotDescription, " Nas popis slotu ");
    strcpy(pInfo->manufacturerID, " Vyrobca slotu ");
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 2;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 2;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

/**
 * Poskytne informacie o danom tokene
 * @param SlotId - identifikator slotu, ktoremu token patri
 * @param pInfo - sem sa naplnia informacie o tokene
 * @return 
 */
CK_RV CK_ENTRY C_GetTokenInfo(CK_SLOT_ID SlotId, CK_TOKEN_INFO_PTR pInfo) {
    ConsoleLog("C_GetTokenInfo entered");

    strcpy(pInfo->label, " popis tokenu ");
    strcpy(pInfo->manufacturerID, " manufacturer ID ");
    strcpy(pInfo->model, " model ");
    strcpy(pInfo->serialNumber, " seriove cislo ");
    pInfo->ulMaxSessionCount = 0;
    pInfo->ulSessionCount = 0; // ???
    pInfo->ulMaxRwSessionCount = 1; // ???
    pInfo->ulRwSessionCount = 0; // ???
    pInfo->ulMaxPinLen = 32; // ???
    pInfo->ulMinPinLen = 1; // ???
    pInfo->ulTotalPublicMemory = -1; // ???
    pInfo->ulFreePublicMemory = -1; // ???
    pInfo->ulTotalPrivateMemory = -1; // ???
    pInfo->ulFreePrivateMemory = -1; // ???
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    strcpy(pInfo->utcTime, "2014102212495500");
    pInfo->flags = 0;

    return CKR_OK;
}

/**
 * Poskytne zoznam mechanizmov, ktore podporuje dany slot
 * @param SlotId - identifikator slotu
 * @param pMechanismList - ak je NULL_PTR, ziskavame pocet mechanizmov, inak ziskavame aj zoznam mechanizmov
 * @param pulCount - sem sa naplni pocet mechanizmov
 * @return 
 */
CK_RV CK_ENTRY C_GetMechanismList(CK_SLOT_ID SlotId, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
    ConsoleLog("C_GetMechanismList entered");

    if (pMechanismList == NULL_PTR) { //ziskavame pocet mechanizmov (1)   
        *pulCount = 1;
    } else { //ziskavame zoznam mechanizmov (2)
        pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN; // ??? strana 70 z navodu vybrat mechanizmus
        *pulCount = 1;
    }

    return CKR_OK;
}

CK_RV CK_ENTRY C_GetMechanismInfo(CK_SLOT_ID SlotId, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
    ConsoleLog("C_GetMechanismInfo entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_InitToken(CK_SLOT_ID SlotId, CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_CHAR_PTR pLabel) {
    ConsoleLog("C_InitToken entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * Zavola sa na zaciatku / po otvoreni relacie
 * @param SlotId - identifikator slotu
 * @param flags
 * @param pApplication
 * @param Notify
 * @param phSession - sem sa posle identifikator novootvorenej relacie. Na ten sa potom moze dalej odkazovat
 * @return 
 */
CK_RV CK_ENTRY C_OpenSession(CK_SLOT_ID SlotId, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    ConsoleLog("C_OpenSession entered");

    *phSession = 1; //pridelene ID relacie, na ktore sa je mozne neskor odkazovat

    return CKR_OK;
}

CK_RV CK_ENTRY C_CloseSession(CK_SESSION_HANDLE hSession) {
    ConsoleLog("C_CloseSession entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_CloseAllSessions(CK_SLOT_ID SlotId) {
    ConsoleLog("C_CloseAllSessions entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    ConsoleLog("C_GetSessionInfo entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen) {
    ConsoleLog("C_Login entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_Logout(CK_SESSION_HANDLE hSession) {
    ConsoleLog("C_Logout entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_InitPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen) { //pozor na parametre
    ConsoleLog("C_InitPIN entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SetPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
    ConsoleLog("C_SetPIN entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
    ConsoleLog("C_GetOperationState entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
    ConsoleLog("C_SetOperationState entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
    ConsoleLog("C_GetFunctionStatus entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_CancelFunction(CK_SESSION_HANDLE hSession) {
    ConsoleLog("C_CancelFunction entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
    ConsoleLog("C_CreateObject entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
    ConsoleLog("C_CopyObject entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    ConsoleLog("C_DestroyObject entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
    ConsoleLog("C_GetObjectSize entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    ConsoleLog("C_GetAttributeValue entered");
    
    //return CKR_OK; //todo

    int i;
    for (i = 0; i < ulCount; i++) {
        ConsoleLogUnsignedLongInt(pTemplate[i].type);
        if (pTemplate[i].type == CKA_TOKEN) {
            ConsoleLog("CKA_TOKEN");
            //*((CK_BBOOL *)pTemplate[i].pValue) = (CK_BBOOL)TRUE;    
            if (pTemplate[i].pValue == NULL_PTR) {
                ConsoleLog("NULL POINTER");
                pTemplate[i].ulValueLen = sizeof (TRUE);
            } else {
                ConsoleLog("NOT NULL POINTER");
                *((CK_BBOOL *) pTemplate[i].pValue) = TRUE;
                //pTemplate[i].ulValueLen = sizeof(TRUE);
            }
            //*((CK_BBOOL *)pTemplate[i].pValue) = TRUE; 
            //pTemplate[i].ulValueLen = (CK_ULONG)-1;
        } else if (pTemplate[i].type == CKA_LABEL) {
            ConsoleLog("CKA_LABEL");
            if (pTemplate[i].pValue == NULL_PTR) {
                ConsoleLog("NULL POINTER");
                pTemplate[i].ulValueLen = sizeof ("Popis nasho tokenu objectu");
            } else {
                ConsoleLog("NOT NULL POINTER");
                pTemplate[i].pValue = "Popis nasho tokenu objectu";
                //pTemplate[i].ulValueLen = sizeof("Popis nasho tokenu objectu");
            }
            //pTemplate[i].pValue = "Popis nasho tokenu objectu"; 
            //pTemplate[i].ulValueLen = sizeof("Popis nasho tokenu objectu");
        } else if (pTemplate[i].type == CKA_CLASS) {
            ConsoleLog("CKA_CLASS");
        } else if (pTemplate[i].type == CKA_PRIVATE) {
            ConsoleLog("CKA_PRIVATE");
        } else if (pTemplate[i].type == CKA_APPLICATION) {
            ConsoleLog("CKA_APPLICATION");
        } else if (pTemplate[i].type == CKA_VALUE) {
            ConsoleLog("CKA_VALUE");
        } else if (pTemplate[i].type == CKA_OBJECT_ID) {
            ConsoleLog("CKA_OBJECT_ID");
        } else if (pTemplate[i].type == CKA_CERTIFICATE_TYPE) {
            ConsoleLog("CKA_CERTIFICATE_TYPE");
        } else if (pTemplate[i].type == CKA_ISSUER) {
            ConsoleLog("CKA_ISSUER");
        } else if (pTemplate[i].type == CKA_SERIAL_NUMBER) {
            ConsoleLog("CKA_SERIAL_NUMBER");
        } else if (pTemplate[i].type == CKA_AC_ISSUER) {
            ConsoleLog("CKA_AC_ISSUER");
        } else if (pTemplate[i].type == CKA_OWNER) {
            ConsoleLog("CKA_OWNER");
        } else if (pTemplate[i].type == CKA_ATTR_TYPES) {
            ConsoleLog("CKA_ATTR_TYPES");
        } else if (pTemplate[i].type == CKA_TRUSTED) {
            ConsoleLog("CKA_TRUSTED");
        } else if (pTemplate[i].type == CKA_KEY_TYPE) {
            ConsoleLog("CKA_KEY_TYPE");
        } else if (pTemplate[i].type == CKA_SUBJECT) {
            ConsoleLog("CKA_SUBJECT");
        } else if (pTemplate[i].type == CKA_ID) {
            ConsoleLog("CKA_ID");
        } else if (pTemplate[i].type == CKA_SENSITIVE) {
            ConsoleLog("CKA_SENSITIVE");
        } else if (pTemplate[i].type == CKA_ENCRYPT) {
            ConsoleLog("CKA_ENCRYPT");
        } else if (pTemplate[i].type == CKA_DECRYPT) {
            ConsoleLog("CKA_DECRYPT");
        } else if (pTemplate[i].type == CKA_WRAP) {
            ConsoleLog("CKA_WRAP");
        } else if (pTemplate[i].type == CKA_UNWRAP) {
            ConsoleLog("CKA_UNWRAP");
        } else if (pTemplate[i].type == CKA_SIGN) {
            ConsoleLog("CKA_SIGN");
        } else if (pTemplate[i].type == CKA_SIGN_RECOVER) {
            ConsoleLog("CKA_SIGN_RECOVER");
        } else if (pTemplate[i].type == CKA_VERIFY) {
            ConsoleLog("CKA_VERIFY");
        } else if (pTemplate[i].type == CKA_VERIFY_RECOVER) {
            ConsoleLog("CKA_VERIFY_RECOVER");
        } else if (pTemplate[i].type == CKA_DERIVE) {
            ConsoleLog("CKA_DERIVE");
        } else if (pTemplate[i].type == CKA_START_DATE) {
            ConsoleLog("CKA_START_DATE");
        } else if (pTemplate[i].type == CKA_END_DATE) {
            ConsoleLog("CKA_END_DATE");
        } else if (pTemplate[i].type == CKA_MODULUS) {
            ConsoleLog("CKA_MODULUS");
        } else if (pTemplate[i].type == CKA_MODULUS_BITS) {
            ConsoleLog("CKA_MODULUS_BITS");
        } else if (pTemplate[i].type == CKA_PUBLIC_EXPONENT) {
            ConsoleLog("CKA_PUBLIC_EXPONENT");
        } else if (pTemplate[i].type == CKA_PRIVATE_EXPONENT) {
            ConsoleLog("CKA_PRIVATE_EXPONENT");
        } else if (pTemplate[i].type == CKA_PRIME_1) {
            ConsoleLog("CKA_PRIME_1");
        } else if (pTemplate[i].type == CKA_PRIME_2) {
            ConsoleLog("CKA_PRIME_2");
        } else if (pTemplate[i].type == CKA_EXPONENT_1) {
            ConsoleLog("CKA_EXPONENT_1");
        } else if (pTemplate[i].type == CKA_EXPONENT_2) {
            ConsoleLog("CKA_EXPONENT_2");
        } else if (pTemplate[i].type == CKA_COEFFICIENT) {
            ConsoleLog("CKA_COEFFICIENT");
        } else if (pTemplate[i].type == CKA_PRIME) {
            ConsoleLog("CKA_PRIME");
        } else if (pTemplate[i].type == CKA_SUBPRIME) {
            ConsoleLog("CKA_SUBPRIME");
        } else if (pTemplate[i].type == CKA_BASE) {
            ConsoleLog("CKA_BASE");
        } else if (pTemplate[i].type == CKA_PRIME_BITS) {
            ConsoleLog("CKA_PRIME_BITS");
        } else if (pTemplate[i].type == CKA_VALUE_BITS) {
            ConsoleLog("CKA_VALUE_BITS");
        } else if (pTemplate[i].type == CKA_VALUE_LEN) {
            ConsoleLog("CKA_VALUE_LEN");
        } else if (pTemplate[i].type == CKA_EXTRACTABLE) {
            ConsoleLog("CKA_EXTRACTABLE");
        } else if (pTemplate[i].type == CKA_LOCAL) {
            ConsoleLog("CKA_LOCAL");
        } else if (pTemplate[i].type == CKA_NEVER_EXTRACTABLE) {
            ConsoleLog("CKA_NEVER_EXTRACTABLE");
        } else if (pTemplate[i].type == CKA_ALWAYS_SENSITIVE) {
            ConsoleLog("CKA_ALWAYS_SENSITIVE");
        } else if (pTemplate[i].type == CKA_KEY_GEN_MECHANISM) {
            ConsoleLog("CKA_KEY_GEN_MECHANISM");
        } else if (pTemplate[i].type == CKA_MODIFIABLE) {
            ConsoleLog("CKA_MODIFIABLE");
        } else {
            ConsoleLog("NIECO INE");
        }

    }


    return CKR_OK;
}

CK_RV CK_ENTRY C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    ConsoleLog("C_SetAttributeValue entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    ConsoleLog("C_FindObjectsInit entered");

    zapamatanyTemplate = pTemplate;
    zapamatanyTemplateCount = ulCount;      
    
    ConsoleLog("C_FindObjectsInit success");
    
    return CKR_OK;

}

CK_RV CK_ENTRY C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    ConsoleLog("C_FindObjects entered");

    char spravaPreTelefon[4096] = "";                
    
    strcat(spravaPreTelefon, "FNDO:");
    
    //info o tom, ci je filter neplatny
    int jeFilterNeplatny = 0;

    int i;
    for (i = 0; i < zapamatanyTemplateCount; i++) {
        //ConsoleLogUnsignedLongInt(zapamatanyTemplate[i].type);
        //printf("%lu\n", *((CK_ULONG *) zapamatanyTemplate[i].pValue));
                
        switch (zapamatanyTemplate[i].type) {
            case CKA_CLASS:                
                
                strcat(spravaPreTelefon, "CKA_CLASS");
                strcat(spravaPreTelefon, "//**||");
                
                ConsoleLog("CKA_CLASS");
                switch (*((CK_ULONG *) zapamatanyTemplate[i].pValue)) {
                    case CKO_CERTIFICATE:                        
                        
                        strcat(spravaPreTelefon, "CKO_CERTIFICATE");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        ConsoleLog("CKO_CERTIFICATE");                        
                        break;

                    default:
                        jeFilterNeplatny = 1;
                        ConsoleLog("UNDEFINED");
                        break;
                }
                break;

            case CKA_TOKEN:
                
                strcat(spravaPreTelefon, "CKA_TOKEN");
                strcat(spravaPreTelefon, "//**||");
                
                ConsoleLog("CKA_TOKEN");
                switch (*((CK_BBOOL *) zapamatanyTemplate[i].pValue)) {
                    case TRUE: //token object
                        
                        strcat(spravaPreTelefon, "TRUE");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        ConsoleLog("TRUE");
                        break;
                    case FALSE: //session object
                        
                        strcat(spravaPreTelefon, "FALSE");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        ConsoleLog("FALSE");
                        break;
                    default:
                        jeFilterNeplatny = 1;
                        ConsoleLog("UNDEFINED");
                        break;
                }
                break;


            case CKA_PRIVATE:
                
                strcat(spravaPreTelefon, "CKA_PRIVATE");
                strcat(spravaPreTelefon, "//**||");
                
                ConsoleLog("CKA_PRIVATE");
                switch (*((CK_BBOOL *) zapamatanyTemplate[i].pValue)) {
                    case TRUE: //token object
                        
                        strcat(spravaPreTelefon, "TRUE");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        ConsoleLog("TRUE");
                        break;
                    case FALSE: //session object
                        
                        strcat(spravaPreTelefon, "FALSE");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        ConsoleLog("FALSE");
                        break;
                    default:
                        jeFilterNeplatny = 1;
                        ConsoleLog("UNDEFINED");
                        break;
                }
                break;

            case CKA_LABEL:
                
                strcat(spravaPreTelefon, "CKA_LABEL");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon,  ((char *) zapamatanyTemplate[i].pValue) );
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_LABEL");
                break;

            case CKA_ISSUER:
                
                strcat(spravaPreTelefon, "CKA_ISSUER");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon, ((char *) zapamatanyTemplate[i].pValue) );
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_ISSUER");
                break;

            case CKA_SERIAL_NUMBER:
                
                strcat(spravaPreTelefon, "CKA_SERIAL_NUMBER");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon, ((char *) zapamatanyTemplate[i].pValue));
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_SERIAL_NUMBER");
                break;

            case CKA_CERTIFICATE_TYPE:
                
                strcat(spravaPreTelefon, "CKA_CERTIFICATE_TYPR");
                strcat(spravaPreTelefon, "//**||");
                
                ConsoleLog("CKA_CERTIFICATE_TYPE");
                switch (*((CK_ULONG *) zapamatanyTemplate[i].pValue)) {
                    case CKC_X_509:
                        ConsoleLog("CKC_X_509");
                        
                        strcat(spravaPreTelefon, "CKC_X_509");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        break;

                    case CKC_X_509_ATTR_CERT:
                        ConsoleLog("CKC_X_ATTR_CERT");
                        
                        strcat(spravaPreTelefon, "CKC_X_ATTR_CERT");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        break;

                    case CKC_VENDOR_DEFINED:
                        ConsoleLog("CKC_VENDOR_DEFINED");
                        
                        strcat(spravaPreTelefon, "CKC_VENDOR_DEFINED");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        break;

                    default:
                        jeFilterNeplatny = 1;
                        ConsoleLog("UNDEFINED");
                        break;
                }
                break;
                
            case CKA_TRUSTED:
                
                strcat(spravaPreTelefon, "CKA_TRUSTED");
                strcat(spravaPreTelefon, "//**||");
                
                ConsoleLog("CKA_TRUSTED");
                switch (*((CK_BBOOL *) zapamatanyTemplate[i].pValue)) {
                    case TRUE:
                        ConsoleLog("TRUE");
                        
                        strcat(spravaPreTelefon, "TRUE");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        break;
                        
                    case FALSE:
                        ConsoleLog("FALSE");
                        
                        strcat(spravaPreTelefon, "FALSE");
                        strcat(spravaPreTelefon, ";?;!;?");
                        
                        break;
                        
                    default:
                        jeFilterNeplatny = 1;
                        ConsoleLog("UNDEFINED");
                        break;
                }
                break;
                
            case CKA_SUBJECT:
                
                strcat(spravaPreTelefon, "CKA_SUBJECT");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon, ((char *) zapamatanyTemplate[i].pValue));
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_SUBJECT");                
                break;
                
            case CKA_ID:
                
                strcat(spravaPreTelefon, "CKA_ID");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon, "TODO");
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_ID");
                break;
                
            case CKA_VALUE:
                
                strcat(spravaPreTelefon, "CKA_VALUE");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon, "TODO");
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_VALUE");
                break;
                
            case CKA_OWNER:
                
                strcat(spravaPreTelefon, "CKA_OWNER");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon, "TODO");
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_OWNER");
                break;
                
            case CKA_AC_ISSUER:
                
                strcat(spravaPreTelefon, "CKA_AC_ISSUER");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon, "TODO");
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_AC_ISSUER");
                break;
              
                
            case CKA_ATTR_TYPES:
                
                strcat(spravaPreTelefon, "CKA_ATTR_TYPES");
                strcat(spravaPreTelefon, "//**||");
                
                strcat(spravaPreTelefon, "TODO");
                strcat(spravaPreTelefon, ";?;!;?");
                
                ConsoleLog("CKA_ATTR_TYPES");
                break;                                

            default:
                jeFilterNeplatny = 1;
                ConsoleLog("POZOR, CHCE NEPODPOROVANY TYP ATRIBUTU");
                break;
        }
    }

    //podla toho, ci je filter r        elevantny alebo nie
    if (jeFilterNeplatny == 1) { //ak je filter neplatny
        ConsoleLog("FILTER JE NEPLATNY");
        *pulObjectCount = 0; //pocet objektov
        return CKR_OK;
    } else { //ak je filter platny        
        
        //posli filterTyp[] a filterHodnota[] do telefonu, spracuj odpoved a podla toho odpovedz PKCS kniznici                        
        //todo poslat spravu telefonu a spracovat odpoved
        ConsoleLog(spravaPreTelefon);
        
        posliSpravuJave(spravaPreTelefon);        
        char spravaZJavy[MAX_PKSC11FIFO_BUF];
        dajSpravuZJavy(spravaZJavy);        
        printf("PRIJATA SPRAVA Z ANDROID TELEFONU: %s", spravaZJavy);
        
        
        *pulObjectCount = 0; //pocet objektov
        return CKR_OK;
    }
}

CK_RV CK_ENTRY C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    ConsoleLog("C_FindObjectsFinal entered");

    return CKR_OK;
}

CK_RV CK_ENTRY C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    ConsoleLog("C_EncryptInit entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
    ConsoleLog("C_Encrypt entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    ConsoleLog("C_EncryptUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
    ConsoleLog("C_EncryptFinal entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    ConsoleLog("C_DecryptInit entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    ConsoleLog("C_Decrypt entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    ConsoleLog("C_DecryptUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
    ConsoleLog("C_DecryptFinal entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
    ConsoleLog("C_DigestInit entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    ConsoleLog("C_Digest entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    ConsoleLog("C_DigestUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
    ConsoleLog("C_DigestKey entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    ConsoleLog("C_DigestFinal entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    ConsoleLog("C_SignInit entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    ConsoleLog("C_Sign entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    ConsoleLog("C_SignUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    ConsoleLog("C_SignFinal entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    ConsoleLog("C_SignRecoverInit entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    ConsoleLog("C_SignRecover entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    ConsoleLog("C_VerifyInit entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    ConsoleLog("C_Verify entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    ConsoleLog("C_VerifyUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    ConsoleLog("C_VerifyFinal entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    ConsoleLog("C_VerifyRecoverInit entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    ConsoleLog("C_VerifyRecover entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    ConsoleLog("C_DigestEncryptUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG lEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    ConsoleLog("C_DecryptDigestUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    ConsoleLog("C_SignEncryptUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    ConsoleLog("C_DecryptVerifyUpdate entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
    ConsoleLog("C_GenerateKey entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
    ConsoleLog("C_GenerateKeyPair entered");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hWrappedKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
    ConsoleLog("C_WrapKey entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phUnwrappedKey) {
    ConsoleLog("C_UnwrapKey entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    ConsoleLog("C_DeriveKey entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    ConsoleLog("C_SeedRandom entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    ConsoleLog("C_GenerateRandom entered");



    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_ENTRY C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
    ConsoleLog("C_WaitForSlotEvent entered");
    return CKR_FUNCTION_NOT_SUPPORTED;
}
