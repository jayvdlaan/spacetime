use spacetime_module as sm;

#[test]
fn descriptor_and_topo_checks() {
    #[derive(Debug)]
    struct A;
    impl sm::core::Module for A {
        const NAME: &'static str = "A";
        const VERSION: sm::core::Version = sm::core::Version::new(0, 1, 0);
        type Deps<'a> = ();
        fn init(
            _c: &mut sm::core::InitCtx,
            _d: Self::Deps<'_>,
        ) -> Result<Self, sm::core::InitError> {
            Ok(A)
        }
    }

    let d = <A as sm::Describe>::descriptor();
    assert_eq!(d.name, "A");

    let nodes = [sm::ModuleNode {
        descriptor: d,
        init: |_c| Ok(()),
        deps: &[],
        start: None,
    }];
    let g = sm::ModuleGraph::new(&nodes);
    let ordered = sm::topo_order(&g).unwrap();
    assert_eq!(ordered.len(), 1);
}
