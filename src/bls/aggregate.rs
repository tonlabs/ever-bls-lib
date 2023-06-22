use super::converters::*;
use super::random_helper::*;
use super::nodes_info::*;
use super::key_gen::*;
use super::sig::*;
use crate::bls::*;
use blst::*;
use blst::min_pk::*;
//use blst::min_sig::*;
use ton_types::{fail, Result};
use std::collections::HashMap;

pub fn aggregate_public_keys(bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    if bls_pks_bytes.len() == 0 {
        fail!("Vector of public keys can not be empty!");
    }
    let mut pks: Vec<PublicKey> = Vec::new();
    for bls_pk in bls_pks_bytes {
        pks.push(convert_public_key_bytes_to_public_key(bls_pk)?);
    }
    let pk_refs: Vec<&PublicKey> = pks.iter().map(|pk| pk).collect();
    let agg = match AggregatePublicKey::aggregate(&pk_refs, true) {
        Ok(agg) => agg,
        Err(err) => fail!("aggregate failure: {:?}", err),
    };
    Ok(agg.to_public_key().to_bytes())
}

pub fn aggregate_public_keys_based_on_nodes_info(bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>, nodes_info_bytes: &Vec<u8>) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    if bls_pks_bytes.len() == 0 {
        fail!("Vector of public keys can not be empty!");
    }
    let nodes_info = NodesInfo::deserialize(nodes_info_bytes)?;
    if bls_pks_bytes.len() != nodes_info.total_num_of_nodes as usize {
        fail!("Vector of public keys is too short!");
    }
    let mut apk_pks_required_refs: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
    for (index, number_of_occurrence) in &nodes_info.map {
        for i in 0..*number_of_occurrence {
            apk_pks_required_refs.push(bls_pks_bytes[*index as usize]);
        }
    }
    let now = Instant::now();
    let result = aggregate_public_keys(&apk_pks_required_refs)?;
    let duration = now.elapsed();

    println!("Time elapsed by !!!aggregate_public_keys is: {:?}", duration);
    Ok(result)
}

pub fn aggregate_two_bls_signatures(sig_bytes_with_nodes_info_1: &Vec<u8>, sig_bytes_with_nodes_info_2: &Vec<u8>) -> Result<Vec<u8>> {
    let bls_sig_1 = BlsSignature::deserialize(sig_bytes_with_nodes_info_1)?;
    let bls_sig_2 = BlsSignature::deserialize(sig_bytes_with_nodes_info_2)?;
    let new_nodes_info = NodesInfo::merge(&bls_sig_1.nodes_info, &bls_sig_2.nodes_info)?;
    let sig1 = convert_signature_bytes_to_signature(&bls_sig_1.sig_bytes)?;
    let sig2 = convert_signature_bytes_to_signature(&bls_sig_2.sig_bytes)?;
    let sig_validate_res = sig1.validate(false); //set true to exclude infinite point, i.e. zero sig
    if sig_validate_res.is_err() {
        fail!("Signature is not in group.");
    }
    let mut agg_sig = AggregateSignature::from_signature(&sig1);
    let res = AggregateSignature::add_signature(&mut agg_sig, &sig2, true);
    if res.is_err() {
        fail!("Failure while concatenate signatures");
    }
    let new_sig = agg_sig.to_signature();
    let new_agg_sig = BlsSignature {
        sig_bytes: new_sig.to_bytes(),
        nodes_info: new_nodes_info,
    };
    let new_agg_sig_bytes = BlsSignature::serialize(&new_agg_sig);
    Ok(new_agg_sig_bytes)
}

pub fn aggregate_bls_signatures(sig_bytes_with_nodes_info_vec: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    if sig_bytes_with_nodes_info_vec.len() == 0 {
        fail!("Vector of signatures can not be empty!");
    }
    let mut bls_sigs: Vec<BlsSignature> = Vec::new();
    for bytes in sig_bytes_with_nodes_info_vec {
        let agg_sig = BlsSignature::deserialize(&bytes)?;
        bls_sigs.push(agg_sig);
    }

    let bls_sigs_refs: Vec<&BlsSignature> = bls_sigs.iter().map(|sig| sig).collect();
    let mut nodes_info_refs: Vec<&NodesInfo> = Vec::new();
    let mut sigs: Vec<Signature> = Vec::new();
    for i in 0..bls_sigs_refs.len() {
        nodes_info_refs.push(&bls_sigs_refs[i].nodes_info);
        let sig = convert_signature_bytes_to_signature(&bls_sigs_refs[i].sig_bytes)?;
        println!("{:?}", &sig.to_bytes());
        //return this part to exclude zero sig
       /* let res = sig.validate(true);
        if res.is_err() {
            fail!("Sig is point of infinity or does not belong to group.");
        }*/
        sigs.push(sig);
    }

    let new_nodes_info = NodesInfo::merge_multiple(&nodes_info_refs)?;

    let sig_refs: Vec<&Signature> = sigs.iter().map(|sig| sig).collect();

    let agg = match AggregateSignature::aggregate(&sig_refs, true) {
        Ok(agg) => agg,
        Err(err) => fail!("aggregate failure: {:?}", err),
    };
    let new_sig = agg.to_signature();
    let new_sig_bytes = convert_signature_to_signature_bytes(new_sig);
    let new_agg_sig = BlsSignature {
        sig_bytes: new_sig_bytes,
        nodes_info: new_nodes_info,
    };
    let new_agg_sig_bytes = BlsSignature::serialize(&new_agg_sig);
    Ok(new_agg_sig_bytes)
}


