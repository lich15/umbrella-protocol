use umbrella_oprf::{
    threshold_combine, BlindedRequest, OprfError, OprfInput, ServerEvaluation, ThresholdConfig,
    WitnessIndex, MAX_INPUT_BYTES,
};

#[test]
fn rfc9497_input_length_boundaries_are_fail_closed() {
    let empty = OprfInput::new(&[]).unwrap_err();
    assert!(matches!(empty, OprfError::EmptyInput));

    let too_large = vec![0x41; MAX_INPUT_BYTES + 1];
    let err = OprfInput::new(&too_large).unwrap_err();
    assert!(matches!(
        err,
        OprfError::InputTooLarge { got, max }
            if got == MAX_INPUT_BYTES + 1 && max == MAX_INPUT_BYTES
    ));

    let max = vec![0x42; MAX_INPUT_BYTES];
    OprfInput::new(&max).expect("max-size OPRF input must remain accepted");
}

#[test]
fn rfc9497_rejects_wrong_wire_lengths_and_bad_points() {
    let short = BlindedRequest::from_bytes(&[0u8; 31]).unwrap_err();
    assert!(matches!(
        short,
        OprfError::WrongWireLength {
            expected: 32,
            got: 31
        }
    ));

    let long = ServerEvaluation::from_bytes(&[0u8; 33]).unwrap_err();
    assert!(matches!(
        long,
        OprfError::WrongWireLength {
            expected: 32,
            got: 33
        }
    ));

    let bad_point = [0xFFu8; 32];
    assert!(matches!(
        BlindedRequest::from_bytes(&bad_point).unwrap_err(),
        OprfError::InvalidRistrettoEncoding
    ));
    assert!(matches!(
        ServerEvaluation::from_bytes(&bad_point).unwrap_err(),
        OprfError::InvalidRistrettoEncoding
    ));
}

#[test]
fn rfc9497_threshold_precheck_rejects_subthreshold_before_any_success() {
    let shares: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> = heapless::Vec::new();
    let err = threshold_combine(&shares, ThresholdConfig::default()).unwrap_err();
    assert!(matches!(
        err,
        OprfError::InsufficientValidEvaluations {
            valid: 0,
            required: 3
        }
    ));
}
