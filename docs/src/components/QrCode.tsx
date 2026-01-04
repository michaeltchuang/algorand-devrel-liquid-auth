import { SignalClient } from "@algorandfoundation/liquid-client/signal";
import { toBase64URL } from "@algorandfoundation/liquid-client/encoding";
import React, { useEffect, useMemo, useState } from "react";
import { useAccountInfo } from "../hooks/useAccountInfo.ts";
import { useAlgod } from "../hooks/useAlgod.ts";
import {
  type Algodv2,
  encodeUnsignedTransaction,
  encodeObj,
  makePaymentTxnWithSuggestedParamsFromObject,
  Transaction,
  waitForConfirmation
} from "algosdk";
import {
  fromBase64Url,
  type ResponseMessage,
  toSignTransactionsParamsRequestMessage
} from "@algorandfoundation/provider";
import { fromResult } from "../hooks/provider.ts";

const url = import.meta.env.PUBLIC_LIQUID_ORIGIN || "michaeltchuang.ngrok.dev";
const INITIAL = "Initializing 🚀";
const PEER_CONNECTED = "Peer connected 🎉";
const SENDING_TRANSACTION = "Requesting Signature 📲";
const RECEIVED_SIGNATURE = "Received Signature 🔏";
const SUBMITTED_TRANSACTION = "Submitted Transaction 🚀";
const TRANSACTION_CONFIRMED = "Transaction Confirmed ✅";
const LINK_REQUEST = "Link Requested 🚚";
const WAITING = "Waiting for Link ⌛";
const LINKED = "Linked 🔗";
const CLOSED = "Closed 🚪";
const ERROR = "Something went wrong 🛑";

type FundAccountProps = {
  address?: string
  onCancel?: React.MouseEventHandler<HTMLButtonElement>
}
function FundAccount({address = "Loading...", onCancel = console.log}){
  return (
    <>
      <h1 className="text-white text-2xl mb-2">Fund Account</h1>
      <p className="text-white">Account is missing funds, you need at least the minimum transaction fee to test</p>
      <input value={address} onChange={()=>{}}/>
      <div className="flex flex-col mt-4 mx-auto gap-2">
        <a role="button" target="_blank" href="https://bank.testnet.algorand.network/" className="px-10 py-2 text-md font-poppins leading-6 border-2 border-liquid-purple text-white">
          Dispenser
        </a>
        <button className="px-10 py-2 text-md font-poppins leading-6 border-2 border-red-600 text-white"
                onClick={onCancel}>
          Cancel
        </button>
      </div>
    </>
  )
}

type SendTransactionProps = {
  disabled?: boolean,
  onCancel?: React.MouseEventHandler<HTMLButtonElement>,
  onSubmit?: React.MouseEventHandler<HTMLButtonElement>,
}

function SendTransaction({ disabled = false, onCancel = console.log, onSubmit = console.log }: SendTransactionProps) {
  return (
    <>
      <h1 className="text-white text-2xl mb-2">Send Transaction</h1>
      <p className="text-white">Send a simple transaction with 0 Amount</p>
      <div className="flex mt-2 mx-auto gap-2">
        <button disabled={disabled} className="px-10 py-2 text-md font-poppins leading-6 border-2 border-liquid-green text-white"
                onClick={onSubmit}>
          Send
        </button>
        <button className="px-10 py-2 text-md font-poppins leading-6 border-2 border-red-600 text-white"
                onClick={onCancel}>
          Cancel
        </button>
      </div>
    </>
  );
}

async function makeTransaction(obj: { to: string, from: string, amount: number }, algod: Algodv2) {
  const suggestedParams = await algod.getTransactionParams().do();
  const txn = makePaymentTxnWithSuggestedParamsFromObject({
    ...obj,
    suggestedParams
  });
  return { suggestedParams, txn };
}

let _txn: Transaction | null = null;
let _wallet: string | null = null;
let _auth: string | null = null;

export function QrCode({ label = true }: { label?: boolean }) {
  const [_wallet_unused, setWallet] = useState<string | null>(null)
  // Liquid Auth
  const [client] = useState<SignalClient>(() => new SignalClient(url));
  const [dc, setDataChannel] = useState<RTCDataChannel | null>(null)
  const [requestId, setRequestId] = useState<string>(SignalClient.generateRequestId());
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);

  // State
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isInFlight, setIsInflight] = useState<boolean>(false);

  // Status String
  const [status, setStatus] = useState<string>(INITIAL);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Transaction State
  const [suggestedParams, setSuggestedParams] = useState<any | null>(null);
  const [confirmedTxId, setConfirmedTxId] = useState<string | null>(null);

  // Account
  const accountInfo = useAccountInfo(_wallet, 3000);
  const isFunded = useMemo(() => {
    return suggestedParams && accountInfo.data && accountInfo.data.amount > suggestedParams.minFee;
  }, [accountInfo]);

  function handleError(_e: Error){
    console.error('❌ Error in QrCode component:', _e);
    console.error('Error details:', {
      message: _e.message,
      stack: _e.stack,
      name: _e.name
    });
    setErrorMessage(_e.message || 'Unknown error occurred');
    setStatus(ERROR)
    setIsInflight(false)
    setIsConnected(false)
  }

  useEffect(() => {
    setIsConnected(false)
    setIsInflight(false)
    setStatus(LINK_REQUEST);

    client.on("link-message", (msg: any) => {
      setStatus(LINKED);
      _wallet = msg.wallet;
      setWallet(msg.wallet)
    });

    client.peer(requestId, "offer").then((dc: any) => {
      setDataChannel(dc)
      setIsConnected(true)
      dc.onmessage = (event: any)=>{
        console.log('📨 Received message over WebRTC:', event.data);
        if(!_txn || !_wallet) {
          console.warn('⚠️  No transaction or wallet set, ignoring message');
          return;
        }
        try{
          // Try to parse JSON first (used for large Falcon responses to avoid CBOR indefinite-length issues)
          const jsonData = JSON.parse(event.data);
          console.log('📋 Parsed as JSON ResponseMessage');
          let data = jsonData as ResponseMessage;
          console.log('Provider ID:', data.result.providerId);
            console.log('Number of stxns:', data.result.stxns?.length);
            console.log('Raw stxns[0]:', data.result.stxns?.[0]);
            console.log('Type of stxns[0]:', typeof data.result.stxns?.[0]);
            
            if (!data.result.stxns || data.result.stxns.length === 0) {
              throw new Error('❌ No signed transactions in response!');
            }
            
            setStatus(RECEIVED_SIGNATURE)
            
            // Check if stxns[0] is already a Uint8Array or if it's base64
            let signedTxnBytes: Uint8Array;
            if (typeof data.result.stxns[0] === 'string') {
              // It's a base64 string, decode it
              console.log('Decoding base64 string, length:', data.result.stxns[0].length);
              console.log('First 20 chars:', data.result.stxns[0].substring(0, 20));
              try {
                signedTxnBytes = fromBase64Url(data.result.stxns[0]);
                console.log('✅ Decoded from base64url, byte length:', signedTxnBytes.length);
              } catch (decodeErr) {
                console.warn('Failed to decode as base64url, trying standard base64...', decodeErr);
                // Try standard base64 as fallback
                signedTxnBytes = Uint8Array.from(atob(data.result.stxns[0]), c => c.charCodeAt(0));
                console.log('✅ Decoded from standard base64, byte length:', signedTxnBytes.length);
              }
            } else if ((data.result.stxns[0] as any) instanceof Uint8Array) {
              // It's already bytes
              signedTxnBytes = data.result.stxns[0];
              console.log('Already Uint8Array, length:', signedTxnBytes.length);
            } else {
              throw new Error('❌ Unexpected stxns[0] format: ' + typeof data.result.stxns[0]);
            }
            
            console.log('First 50 bytes:', Array.from(signedTxnBytes.slice(0, 50)));
            
            // Check what type of signature/transaction we received
            let finalTxnBytes: Uint8Array;
            
            if (signedTxnBytes.length === 64) {
              // This is just an Ed25519 signature (Algo25 or HdKey case)
              console.log('📝 Received Ed25519 signature (64 bytes), attaching to transaction...');
              console.log('Transaction sender:', _txn.from.toString());
              console.log('Signature address:', (data.result as any).address);
              
              // Create a signed transaction object with the signature
              const signedTxn = {
                txn: _txn.get_obj_for_encoding(),
                sig: signedTxnBytes
              };
              
              // Encode the signed transaction as msgpack
              finalTxnBytes = encodeObj(signedTxn);
              console.log('✅ Attached signature, final transaction length:', finalTxnBytes.length);
              
            } else {
              // This is a full signed transaction or transaction group (including Falcon)
              console.log('📦 Received full signed transaction/group');
              finalTxnBytes = signedTxnBytes;
              console.log('Transaction bytes length:', finalTxnBytes.length);
            }
            
            // Send the signed transaction
            console.log('📤 Sending transaction to network...');
            
            algod.sendRawTransaction(finalTxnBytes).do().then(({txId})=>{
              console.log('✅ Transaction submitted! TxID:', txId);
              console.log('📊 View transaction: https://testnet.explorer.perawallet.app/tx/' + txId);
              
              setConfirmedTxId(txId);
              setStatus(SUBMITTED_TRANSACTION)
              
              waitForConfirmation(algod, txId, 4).then(()=>{
                  console.log('✅ Transaction confirmed!');
                  setStatus(TRANSACTION_CONFIRMED)
                  setIsInflight(false)
              });
            }).catch((err) => {
              console.error('❌ Error sending transaction:', err);
              handleError(err);
            });
        } catch (jsonErr) {
          // Not JSON, try CBOR
          console.log('Not JSON, trying CBOR');
          try {
            let data = fromResult(event.data) as ResponseMessage;
            console.log('✅ Decoded CBOR ResponseMessage');
            console.log('Provider ID:', data.result.providerId);
            console.log('Number of stxns:', data.result.stxns?.length);
            console.log('Raw stxns[0]:', data.result.stxns?.[0]);
            console.log('Type of stxns[0]:', typeof data.result.stxns?.[0]);
            
            if (!data.result.stxns || data.result.stxns.length === 0) {
              throw new Error('❌ No signed transactions in response!');
            }
            
            setStatus(RECEIVED_SIGNATURE)
            
            // Check if stxns[0] is already a Uint8Array or if it's base64
            let signedTxnBytes: Uint8Array;
            if (typeof data.result.stxns[0] === 'string') {
              // It's a base64 string, decode it
              console.log('Decoding base64 string, length:', data.result.stxns[0].length);
              console.log('First 20 chars:', data.result.stxns[0].substring(0, 20));
              try {
                signedTxnBytes = fromBase64Url(data.result.stxns[0]);
                console.log('✅ Decoded from base64url, byte length:', signedTxnBytes.length);
              } catch (decodeErr) {
                console.warn('Failed to decode as base64url, trying standard base64...', decodeErr);
                // Try standard base64 as fallback
                signedTxnBytes = Uint8Array.from(atob(data.result.stxns[0]), c => c.charCodeAt(0));
                console.log('✅ Decoded from standard base64, byte length:', signedTxnBytes.length);
              }
            } else if ((data.result.stxns[0] as any) instanceof Uint8Array) {
              // It's already bytes
              signedTxnBytes = data.result.stxns[0];
              console.log('Already Uint8Array, length:', signedTxnBytes.length);
            } else {
              throw new Error('❌ Unexpected stxns[0] format: ' + typeof data.result.stxns[0]);
            }
            
            console.log('First 50 bytes:', Array.from(signedTxnBytes.slice(0, 50)));
            
            // Check what type of signature/transaction we received
            let finalTxnBytes: Uint8Array;
            
            if (signedTxnBytes.length === 64) {
              // This is just an Ed25519 signature (Algo25 or HdKey case)
              console.log('📝 Received Ed25519 signature (64 bytes), attaching to transaction...');
              console.log('Transaction sender:', _txn.from.toString());
              console.log('Signature address:', (data.result as any).address);
              
              // Create a signed transaction object with the signature
              const signedTxn = {
                txn: _txn.get_obj_for_encoding(),
                sig: signedTxnBytes
              };
              
              // Encode the signed transaction as msgpack
              finalTxnBytes = encodeObj(signedTxn);
              console.log('✅ Attached signature, final transaction length:', finalTxnBytes.length);
              
            } else {
              // This is a full signed transaction or transaction group (including Falcon)
              console.log('📦 Received full signed transaction/group');
              finalTxnBytes = signedTxnBytes;
              console.log('Transaction bytes length:', finalTxnBytes.length);
            }
            
            // Send the signed transaction
            console.log('📤 Sending transaction to network...');
            
            algod.sendRawTransaction(finalTxnBytes).do().then(({txId})=>{
              console.log('✅ Transaction submitted! TxID:', txId);
              console.log('📊 View transaction: https://testnet.explorer.perawallet.app/tx/' + txId);
              
              setConfirmedTxId(txId);
              setStatus(SUBMITTED_TRANSACTION)
              
              waitForConfirmation(algod, txId, 4).then(()=>{
                  console.log('✅ Transaction confirmed!');
                  setStatus(TRANSACTION_CONFIRMED)
                  setIsInflight(false)
              });
            }).catch((err) => {
              console.error('❌ Error sending transaction:', err);
              handleError(err);
            });
          } catch (cborErr: any) {
            console.error('❌ CBOR decode error:', cborErr);
            if (cborErr.message?.includes('Indefinite length')) {
              console.log('💡 TIP: For Falcon transactions, send the response as JSON instead of CBOR');
              handleError(new Error('CBOR encoding error: Send large responses as JSON to avoid indefinite-length encoding issues.'));
            } else {
              handleError(cborErr);
            }
          }
        }
      }
      setStatus(PEER_CONNECTED);
    }).catch(handleError);

    client.qrCode().then((url: string) => {
      setQrCodeUrl(url);
      setStatus(WAITING);
    }).catch(handleError);
    return () => {
      client.close();
      setStatus(CLOSED);
    };
  }, [requestId]);

  const algod = useAlgod();

  // Load Suggested Params
  useEffect(() => {
    algod.getTransactionParams().do().then((params) => {
      setSuggestedParams(params);
    }).catch(handleError);
  }, []);

  useEffect(() => {
    if(accountInfo.data?.['auth-addr']){
      _auth = accountInfo.data['auth-addr']
    }
  }, [accountInfo]);

  function handleSubmit() {
    if (!accountInfo.data || !isFunded || !dc || !_wallet) return;
    setStatus(SENDING_TRANSACTION);
    setIsInflight(true)
    makeTransaction({
      to: _wallet,
      from: _wallet,
      amount: 0
    }, algod)
      .then(({ suggestedParams, txn }) => {
        _txn = txn;
        setSuggestedParams(suggestedParams);
        dc.send(toSignTransactionsParamsRequestMessage(SignalClient.generateRequestId(), "02657eaf-be17-4efc-b0a4-19d654b2448e", [{ txn: toBase64URL(encodeUnsignedTransaction(txn)) }]))
      })
      .catch(handleError);
  }

  function Status() {
    if(status === TRANSACTION_CONFIRMED) {
      // Use the confirmed TxID from the network, or fall back to computing from original transaction
      const txId = confirmedTxId || _txn?.txID();
      return <a role="button" target="_blank" href={`https://testnet.explorer.perawallet.app/tx/${txId}`} className="relative -inset-y-14 text-xl text-liquid-blue mt-2 inline">{status}</a>;
    }
    return <p className="relative -inset-y-14 text-white text-xl mt-2 inline">{status}</p>;
  }

  return <div className="w-80 h-80 flex justify-center">
    {label && <Status />}
    {qrCodeUrl &&
      <a className={"absolute max-w-80"} href={client.deepLink(requestId)}>
        <img className="!mt-0" src={qrCodeUrl} alt="Algorand QRCode" />
      </a>
    }
    {isConnected && <div className="absolute flex flex-col bg-gray-800/[.98] p-6 h-80 justify-center max-w-80">
      {isFunded &&
        <SendTransaction disabled={isInFlight} onSubmit={handleSubmit} onCancel={() => setRequestId(SignalClient.generateRequestId())} />}
      {!isFunded && <FundAccount address={accountInfo.data!!.address} onCancel={() => setRequestId(SignalClient.generateRequestId())} />}
    </div>}
  </div>;
}
