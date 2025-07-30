use std::error::Error;
use std::fmt;
use std::fs::File;
use std::panic;

use halo2_axiom::{
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::PrimeField,
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error as PlonkError, Instance, Selector, VerifyingKey,
    },
    poly::{
        commitment::Params,
        kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    circuit::{SimpleFloorPlanner, Layouter, Value},
};
use rand::rngs::OsRng;

static INIT_PROTOCOL: once_cell::sync::OnceCell<()> = once_cell::sync::OnceCell::new();

#[derive(Debug)]
struct ZkpError(String);

impl fmt::Display for ZkpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ZKP error: {}", self.0)
    }
}

impl Error for ZkpError {}


#[cxx::bridge]
mod ffi {
    extern "Rust" {
        fn verify_plonk_halo2_kzg_bn2s6(
            proof: &[u8],
            vk: &[u8],
            public_inputs: &[Vec<u8>],
            params: &[u8],
        ) -> bool;
    }
}

fn initialize_protocol() {
    INIT_PROTOCOL.get_or_init(|| {
        eprintln!("🔧 Initializing ZKP protocol...");
    });
}

pub fn verify_plonk_halo2_kzg_bn2s6(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    public_inputs_bytes: &[Vec<u8>],
    params_bytes: &[u8],
) -> bool {
    initialize_protocol();

    let result = panic::catch_unwind(|| -> Result<bool, ZkpError> {
        let params = ParamsKZG::<Bn256>::read(&mut &params_bytes[..])
            .map_err(|e| ZkpError(format!("Failed to read params: {}", e)))?;

        let vk = VerifyingKey::<G1Affine>::read::<_, MyCircuit>(
            &mut &vk_bytes[..],
            halo2_axiom::SerdeFormat::RawBytes,
            (),
        ).map_err(|e| ZkpError(format!("Failed to deserialize VerifyingKey: {}", e)))?;

        let instances_vec: Vec<Fr> = public_inputs_bytes
            .get(0)
            .ok_or_else(|| ZkpError("Public inputs array is empty".to_string()))?
            .chunks_exact(32)
            .map(|bytes| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Fr::from_repr(arr).unwrap()
            })
            .collect();
        let instances = [instances_vec.as_slice()];

        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof_bytes);

        let verification_result = verify_proof::<_, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[&instances],
            &mut transcript,
        );

        Ok(verification_result.is_ok())
    });

    match result {
        Ok(Ok(true)) => {
            true
        },
        Ok(Ok(false)) => {
            false
        },
        Ok(Err(e)) => {
            false
        },
        Err(_) => {
            false
        }
    }
}

#[derive(Default, Clone)]
struct MyCircuit {
    a: Value<Fr>,
    b: Value<Fr>,
}

#[derive(Clone)]
struct MyConfig {
    advice: [Column<Advice>; 2],
    instance: Column<Instance>,
    s_mul: Selector,
}

impl Circuit<Fr> for MyCircuit {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn params(&self) -> Self::Params {
        ()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let s_mul = meta.selector();
        
        meta.enable_equality(instance);
        
        meta.create_gate("mul gate", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_instance(instance, Rotation::cur());
            let s_mul = meta.query_selector(s_mul);
            vec![s_mul * (lhs * rhs - out)]
        });

        MyConfig {
            advice,
            instance,
            s_mul,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), PlonkError> {
        layouter.assign_region(
            || "main",
            |mut region| {
                config.s_mul.enable(&mut region, 0)?;
                region.assign_advice(config.advice[0], 0, self.a);
                region.assign_advice(config.advice[1], 0, self.b);
                
                Ok(())
            },
        )
    }
}