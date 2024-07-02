// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

use super::{Extension, ExtensionData, NewExtensionError};

/// new extension with no data, id and size corresponding
#[test]
fn test_new_extension_001() {
    let extension = Extension::new(256,&[]);

    let extension_exp = Extension { id: 256, data: ExtensionData::NoData};


    match extension {
        Ok(ext) => assert_eq!(ext, extension_exp),
        Err(e) => panic!("Expected Ok but got Err {:?}",e),
    } 
}

/// new extension with no 2B data, id and size corresponding
#[test]
fn test_new_extension_002() {
    let  data = [4, 5];
    let extension = Extension::new(512,&data);

    let extension_exp = Extension { id: 512, data: ExtensionData::Data2(data)};


    match extension {
        Ok(ext) => assert_eq!(ext, extension_exp),
        Err(e) => panic!("Expected Ok but got Err {:?}",e),
    } 
}

/// new extension with 4b data, id and size corresponding
#[test]
fn test_new_extension_003() {
    let  data = [b'A',b'A',b'A',b'A'];
    let extension = Extension::new(768,&data);

    let extension_exp = Extension { id: 768, data: ExtensionData::Data4(data)};


    match extension {
        Ok(ext) => assert_eq!(ext, extension_exp),
        Err(e) => panic!("Expected Ok but got Err {:?}",e),
    } 
}
/// new extension with 6b data, id and size corresponding
#[test]
fn test_new_extension_004() {
    let  data = [b'A',b'A',b'A',b'A',b'B',b'B'];
    let extension = Extension::new(1024,&data);

    let extension_exp = Extension { id: 1024, data: ExtensionData::Data6(data)};


    match extension {
        Ok(ext) => assert_eq!(ext, extension_exp),
        Err(e) => panic!("Expected Ok but got Err {:?}",e),
    } 
}
/// new extension with 8b data, id and size corresponding
#[test]
fn test_new_extension_005() {
    let  data = [b'A',b'A',b'A',b'A',b'A',b'A',b'A',b'A'];
    let extension = Extension::new(1280,&data);

    let extension_exp = Extension { id: 1280, data: ExtensionData::Data8(data)};


    match extension {
        Ok(ext) => assert_eq!(ext, extension_exp),
        Err(e) => panic!("Expected Ok but got Err {:?}",e),
    } 
}

/// new mandatory extension with 21 bytes of data, id and type corresponding
#[test]
fn test_new_extension_006() {
    let  data = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20];
    let extension = Extension::new(121,&data);

    let extension_exp = Extension { id: 121, data: ExtensionData::MandatoryData(data.to_vec())};


    match extension {
        Ok(ext) => assert_eq!(ext, extension_exp),
        Err(e) => panic!("Expected Ok but got Err {:?}",e),
    } 
}


/// new extension with no data, id and size not corresponding
#[test]
fn test_new_extension_007() {
    let extension = Extension::new(512,&[]);

    let exp_err = NewExtensionError::IdAndVecSizeNotMatchingError;


    match extension {
        Ok(ext) => panic!("Expected Err but got Ok {:?}",ext),
        Err(e) => assert_eq!(e, exp_err),
    } 
}

/// new extension with no 2B data, id and size not corresponding
#[test]
fn test_new_extension_008() {
    let  data = [4, 5];
    let extension = Extension::new(768,&data);

    let exp_err = NewExtensionError::IdAndVecSizeNotMatchingError;


    match extension {
        Ok(ext) => panic!("Expected Err but got Ok {:?}",ext),
        Err(e) => assert_eq!(e, exp_err),
    } 
}

/// new extension with 4b data, id and size not corresponding
#[test]
fn test_new_extension_009() {
    let  data = [b'A',b'A',b'A',b'A'];
    let extension = Extension::new(1024,&data);

    let exp_err = NewExtensionError::IdAndVecSizeNotMatchingError;


    match extension {
        Ok(ext) => panic!("Expected Err but got Ok {:?}",ext),
        Err(e) => assert_eq!(e, exp_err),
    } 
}
/// new extension with 6b data, id and size not corresponding
#[test]
fn test_new_extension_010() {
    let  data = [b'A',b'A',b'A',b'A',b'B',b'B'];
    let extension = Extension::new(1300,&data);

    let exp_err = NewExtensionError::IdAndVecSizeNotMatchingError;


    match extension {
        Ok(ext) => panic!("Expected Err but got Ok {:?}",ext),
        Err(e) => assert_eq!(e, exp_err),
    } 
}
/// new extension with 8b data, id and size not corresponding
#[test]
fn test_new_extension_011() {
    let  data = [b'A',b'A',b'A',b'A',b'A',b'A',b'A',b'A'];
    let extension = Extension::new(700,&data);

    let exp_err = NewExtensionError::IdAndVecSizeNotMatchingError;


    match extension {
        Ok(ext) => panic!("Expected Err but got Ok {:?}",ext),
        Err(e) => assert_eq!(e, exp_err),
    } 
}

/// new mandatory extension with 21 bytes of data, id and type not corresponding
#[test]
fn test_new_extension_012() {
    let  data = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20];
    let extension = Extension::new(258,&data);

    let exp_err = NewExtensionError::IdAndVecSizeNotMatchingError;


    match extension {
        Ok(ext) => panic!("Expected Err but got Ok {:?}",ext),
        Err(e) => assert_eq!(e, exp_err),
    } 
}