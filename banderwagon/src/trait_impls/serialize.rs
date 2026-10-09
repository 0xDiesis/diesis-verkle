use crate::Element;
use ark_ec::{twisted_edwards::TECurveConfig, CurveGroup};
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsProjective};
use ark_ff::{Field, Zero};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Valid, Write,
};
// Use Arkworks I/O traits so serialization also builds without its std feature.
impl CanonicalSerialize for Element {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            ark_serialize::Compress::Yes => {
                writer.write_all(&self.to_bytes())?;
                Ok(())
            }
            ark_serialize::Compress::No => self.0.into_affine().serialize_uncompressed(writer),
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        match compress {
            ark_serialize::Compress::Yes => Element::compressed_serialized_size(),
            ark_serialize::Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl Valid for Element {
    fn check(&self) -> Result<(), SerializationError> {
        let p = &self.0;
        let z2 = p.z.square();
        let x2 = p.x.square();
        let y2 = p.y.square();
        // Extended-projective Edwards equation, plus the quotient's QR test.
        // Multiplication by z^2 preserves quadratic residuosity for z != 0.
        let valid = !p.z.is_zero()
            && p.t * p.z == p.x * p.y
            && (BandersnatchConfig::COEFF_A * x2 + y2) * z2
                == z2.square() + BandersnatchConfig::COEFF_D * x2 * y2
            && (z2 - BandersnatchConfig::COEFF_A * x2).legendre().is_qr();
        if valid {
            Ok(())
        } else {
            Err(SerializationError::InvalidData)
        }
    }
}

impl CanonicalDeserialize for Element {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        fn deserialize_with_no_validation<R: Read>(
            mut reader: R,
            compress: ark_serialize::Compress,
        ) -> Result<Element, SerializationError> {
            match compress {
                ark_serialize::Compress::Yes => {
                    let mut bytes = [0u8; Element::compressed_serialized_size()];
                    if let Err(err) = reader.read_exact(&mut bytes) {
                        return Err(SerializationError::IoError(err));
                    }

                    match Element::from_bytes(&bytes) {
                        Some(element) => Ok(element),
                        None => Err(SerializationError::InvalidData),
                    }
                }
                ark_serialize::Compress::No => {
                    let point = EdwardsProjective::deserialize_uncompressed_unchecked(reader)?;
                    Ok(Element(point))
                }
            }
        }

        match validate {
            ark_serialize::Validate::Yes => {
                let element = deserialize_with_no_validation(reader, compress)?;
                element.check()?;
                Ok(element)
            }
            ark_serialize::Validate::No => deserialize_with_no_validation(reader, compress),
        }
    }
}
