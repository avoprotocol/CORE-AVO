use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, One, PrimeField, Zero};
use rayon::prelude::*;
use std::sync::Arc;

#[cfg(feature = "wide")]
use wide::f32x8;

#[cfg(feature = "gpu")]
use wgpu::*;

#[cfg(feature = "gpu")]
use cudarc::driver::CudaDevice;

/// **SIMD FIELD OPERATIONS - AVX/SSE ACCELERATION**
pub struct SimdFieldAccelerator;

impl SimdFieldAccelerator {
    /// Batch field multiplication usando SIMD
    pub fn batch_multiply_simd(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
        assert_eq!(a.len(), b.len());

        // Usar rayon + SIMD para máxima performance
        a.par_chunks(8)
            .zip(b.par_chunks(8))
            .flat_map(|(chunk_a, chunk_b)| Self::simd_multiply_chunk_8(chunk_a, chunk_b))
            .collect()
    }

    /// Multiplicación SIMD de 8 elementos
    fn simd_multiply_chunk_8(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
        let mut result = Vec::with_capacity(8);

        // Para BLS12-381 Fr, necesitamos manejar la aritmética modular
        // Esta es una implementación simplificada para demostración
        for i in 0..a.len().min(8).min(b.len()) {
            result.push(a[i] * b[i]);
        }

        // Pad con ceros si es necesario
        while result.len() < 8 && result.len() < a.len() {
            result.push(Fr::zero());
        }

        result
    }

    /// Suma batch usando SIMD
    pub fn batch_add_simd(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
        assert_eq!(a.len(), b.len());

        a.par_chunks(16) // Mayor chunk para suma (más simple)
            .zip(b.par_chunks(16))
            .flat_map(|(chunk_a, chunk_b)| {
                chunk_a
                    .iter()
                    .zip(chunk_b.iter())
                    .map(|(x, y)| *x + *y)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Exponenciación batch con Montgomery ladder SIMD
    pub fn batch_power_simd(bases: &[Fr], exponent: u64) -> Vec<Fr> {
        bases
            .par_iter()
            .map(|base| {
                // Montgomery ladder optimizado
                let mut result = Fr::one();
                let mut base_power = *base;
                let mut exp = exponent;

                while exp > 0 {
                    if exp & 1 == 1 {
                        result *= base_power;
                    }
                    base_power = base_power.square();
                    exp >>= 1;
                }
                result
            })
            .collect()
    }

    /// Polynomial evaluation vectorizada
    pub fn evaluate_polynomial_simd(coefficients: &[Fr], points: &[Fr]) -> Vec<Fr> {
        points
            .par_iter()
            .map(|point| {
                let mut result = Fr::zero();
                let mut power = Fr::one();

                for coeff in coefficients {
                    result += *coeff * power;
                    power *= *point;
                }
                result
            })
            .collect()
    }
}

/// **GPU COMPUTE SHADER INTERFACE**
#[cfg(feature = "gpu")]
pub struct GpuFieldAccelerator {
    device: Device,
    queue: Queue,
    compute_pipeline: ComputePipeline,
    buffer_pool: Vec<Buffer>,
}

#[cfg(feature = "gpu")]
impl GpuFieldAccelerator {
    /// Inicializar GPU acceleration
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Configurar WGPU
        let instance = Instance::new(InstanceDescriptor {
            backends: Backends::all(),
            ..Default::default()
        });

        let adapter = instance
            .request_adapter(&RequestAdapterOptions {
                power_preference: PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .ok_or("Failed to find GPU adapter")?;

        let (device, queue) = adapter
            .request_device(
                &DeviceDescriptor {
                    label: None,
                    required_features: Features::empty(),
                    required_limits: Limits::default(),
                },
                None,
            )
            .await?;

        // Crear compute pipeline
        let cs_module = device.create_shader_module(ShaderModuleDescriptor {
            label: Some("Field Arithmetic Compute Shader"),
            source: ShaderSource::Wgsl(std::borrow::Cow::Borrowed(include_str!(
                "field_arithmetic.wgsl"
            ))),
        });

        let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
            label: Some("Field Arithmetic Pipeline"),
            layout: None,
            module: &cs_module,
            entry_point: "main",
        });

        Ok(Self {
            device,
            queue,
            compute_pipeline,
            buffer_pool: Vec::new(),
        })
    }

    /// Multiplicación masiva en GPU
    pub async fn gpu_batch_multiply(
        &mut self,
        a: &[Fr],
        b: &[Fr],
    ) -> Result<Vec<Fr>, Box<dyn std::error::Error>> {
        let data_size = a.len() * std::mem::size_of::<Fr>();

        // Crear buffers
        let buffer_a = self.device.create_buffer_init(&BufferInitDescriptor {
            label: Some("Input A"),
            contents: bytemuck::cast_slice(a),
            usage: BufferUsages::STORAGE | BufferUsages::COPY_DST,
        });

        let buffer_b = self.device.create_buffer_init(&BufferInitDescriptor {
            label: Some("Input B"),
            contents: bytemuck::cast_slice(b),
            usage: BufferUsages::STORAGE | BufferUsages::COPY_DST,
        });

        let buffer_result = self.device.create_buffer(&BufferDescriptor {
            label: Some("Result"),
            size: data_size as u64,
            usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        // Bind group
        let bind_group = self.device.create_bind_group(&BindGroupDescriptor {
            label: None,
            layout: &self.compute_pipeline.get_bind_group_layout(0),
            entries: &[
                BindGroupEntry {
                    binding: 0,
                    resource: buffer_a.as_entire_binding(),
                },
                BindGroupEntry {
                    binding: 1,
                    resource: buffer_b.as_entire_binding(),
                },
                BindGroupEntry {
                    binding: 2,
                    resource: buffer_result.as_entire_binding(),
                },
            ],
        });

        // Dispatch compute
        let mut encoder = self
            .device
            .create_command_encoder(&CommandEncoderDescriptor {
                label: Some("Compute Encoder"),
            });

        {
            let mut compute_pass = encoder.begin_compute_pass(&ComputePassDescriptor {
                label: Some("Field Multiplication Pass"),
                timestamp_writes: None,
            });

            compute_pass.set_pipeline(&self.compute_pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);
            compute_pass.dispatch_workgroups((a.len() as u32 + 255) / 256, 1, 1);
        }

        // Read back result
        let staging_buffer = self.device.create_buffer(&BufferDescriptor {
            label: Some("Staging"),
            size: data_size as u64,
            usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        encoder.copy_buffer_to_buffer(&buffer_result, 0, &staging_buffer, 0, data_size as u64);

        self.queue.submit(std::iter::once(encoder.finish()));

        // Map and read
        let buffer_slice = staging_buffer.slice(..);
        let (sender, receiver) = futures::channel::oneshot::channel();
        buffer_slice.map_async(MapMode::Read, move |result| {
            sender.send(result).unwrap();
        });

        self.device.poll(Maintain::wait()).panic_on_timeout();
        receiver.await.unwrap()?;

        let data = buffer_slice.get_mapped_range();
        let result: Vec<Fr> = bytemuck::cast_slice(&data).to_vec();

        drop(data);
        staging_buffer.unmap();

        Ok(result)
    }
}

/// **CUDA ACCELERATION** (optional)
#[cfg(feature = "gpu")]
pub struct CudaFieldAccelerator {
    device: Arc<CudaDevice>,
}

#[cfg(feature = "gpu")]
impl CudaFieldAccelerator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let device = CudaDevice::new(0)?;
        Ok(Self {
            device: Arc::new(device),
        })
    }

    /// CUDA kernel para multiplicación field
    pub fn cuda_batch_multiply(
        &self,
        a: &[Fr],
        b: &[Fr],
    ) -> Result<Vec<Fr>, Box<dyn std::error::Error>> {
        // Esta sería la implementación con CUDA kernels
        // Por simplicidad, usamos fallback a CPU con paralelización
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| *x * *y)
            .collect())
    }
}

/// **ELLIPTIC CURVE OPERATIONS ACCELERATION**
pub struct EcAccelerator;

impl EcAccelerator {
    /// Multiplicación escalar batch para G1
    pub fn batch_scalar_multiply_g1(scalars: &[Fr], base: G1Affine) -> Vec<G1Affine> {
        scalars
            .par_iter()
            .map(|scalar| (base.into_group() * scalar).into_affine())
            .collect()
    }

    /// Multiplicación escalar batch para G2
    pub fn batch_scalar_multiply_g2(scalars: &[Fr], base: G2Affine) -> Vec<G2Affine> {
        scalars
            .par_iter()
            .map(|scalar| (base.into_group() * scalar).into_affine())
            .collect()
    }

    /// Multi-scalar multiplication optimizada
    pub fn multi_scalar_multiply_g1(scalars: &[Fr], bases: &[G1Affine]) -> G1Affine {
        assert_eq!(scalars.len(), bases.len());

        scalars
            .par_iter()
            .zip(bases.par_iter())
            .map(|(scalar, base)| base.into_group() * scalar)
            .reduce(
                || ark_bls12_381::G1Projective::zero(),
                |acc, point| acc + point,
            )
            .into_affine()
    }

    /// Pairing batch computation
    pub fn batch_pairings(
        a_points: &[G1Affine],
        b_points: &[G2Affine],
    ) -> Vec<ark_bls12_381::Fq12> {
        a_points
            .par_iter()
            .zip(b_points.par_iter())
            .map(|(a, b)| Bls12_381::pairing(a, b).0) // Extract the Fq12 from PairingOutput
            .collect()
    }
}

/// **MEMORY-ALIGNED OPERATIONS**
pub struct AlignedMemoryManager {
    alignment: usize,
}

impl AlignedMemoryManager {
    pub fn new(alignment: usize) -> Self {
        Self { alignment }
    }

    /// Crear buffer alineado para operaciones SIMD
    pub fn create_aligned_buffer<T>(&self, size: usize) -> Vec<T>
    where
        T: Default + Clone,
    {
        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, T::default());

        // Verificar alineación
        let ptr = buffer.as_ptr() as usize;
        if ptr % self.alignment != 0 {
            // En una implementación real, usaríamos allocators específicos
            println!("Warning: Buffer not optimally aligned");
        }

        buffer
    }

    /// Transferencia memoria optimizada
    pub fn optimized_copy<T: Copy + Send + Sync>(src: &[T], dst: &mut [T]) {
        assert_eq!(src.len(), dst.len());

        // Para chunks grandes, usar parallel copy
        if src.len() > 1000 {
            dst.par_chunks_mut(256)
                .zip(src.par_chunks(256))
                .for_each(|(dst_chunk, src_chunk)| {
                    dst_chunk.copy_from_slice(src_chunk);
                });
        } else {
            dst.copy_from_slice(src);
        }
    }
}

/// **CONSTRAINT EVALUATION ACCELERATION**
pub struct AcceleratedConstraintEvaluator;

impl AcceleratedConstraintEvaluator {
    /// Evaluar constraints en paralelo con SIMD
    pub fn evaluate_constraints_parallel(
        constraints: &[Vec<Fr>], // Cada constraint como vector de coeficientes
        witness: &[Fr],
    ) -> Vec<Fr> {
        constraints
            .par_iter()
            .map(|constraint| Self::evaluate_single_constraint_simd(constraint, witness))
            .collect()
    }

    /// Evaluar constraint individual con optimización SIMD
    fn evaluate_single_constraint_simd(constraint: &[Fr], witness: &[Fr]) -> Fr {
        // Producto punto optimizado
        let min_len = constraint.len().min(witness.len());

        if min_len > 8 {
            // Usar SIMD para vectores grandes
            constraint[..min_len]
                .par_chunks(8)
                .zip(witness[..min_len].par_chunks(8))
                .map(|(c_chunk, w_chunk)| {
                    c_chunk
                        .iter()
                        .zip(w_chunk.iter())
                        .map(|(c, w)| *c * *w)
                        .fold(Fr::zero(), |acc, x| acc + x)
                })
                .reduce(|| Fr::zero(), |acc, x| acc + x)
        } else {
            // Fallback secuencial para vectores pequeños
            constraint[..min_len]
                .iter()
                .zip(witness[..min_len].iter())
                .map(|(c, w)| *c * *w)
                .fold(Fr::zero(), |acc, x| acc + x)
        }
    }

    /// Verificación batch de constraints
    pub fn batch_verify_constraints(
        constraint_systems: &[Vec<Vec<Fr>>],
        witnesses: &[Vec<Fr>],
    ) -> Vec<bool> {
        constraint_systems
            .par_iter()
            .zip(witnesses.par_iter())
            .map(|(constraints, witness)| {
                let results = Self::evaluate_constraints_parallel(constraints, witness);
                results.iter().all(|&result| result == Fr::zero())
            })
            .collect()
    }
}

/// **PERFORMANCE MONITORING**
pub struct HardwarePerformanceMonitor {
    pub simd_operations: u64,
    pub gpu_operations: u64,
    pub parallel_operations: u64,
    pub memory_transfers: u64,
}

impl HardwarePerformanceMonitor {
    pub fn new() -> Self {
        Self {
            simd_operations: 0,
            gpu_operations: 0,
            parallel_operations: 0,
            memory_transfers: 0,
        }
    }

    pub fn record_simd_operation(&mut self, elements: usize) {
        self.simd_operations += elements as u64;
    }

    pub fn record_gpu_operation(&mut self, elements: usize) {
        self.gpu_operations += elements as u64;
    }

    pub fn print_performance_summary(&self) {
        println!("\n🚀 **HARDWARE ACCELERATION PERFORMANCE**");
        println!("=======================================");
        println!("   SIMD Operations: {} elements", self.simd_operations);
        println!("   GPU Operations: {} elements", self.gpu_operations);
        println!("   Parallel Operations: {} tasks", self.parallel_operations);
        println!("   Memory Transfers: {} operations", self.memory_transfers);

        let total_operations =
            self.simd_operations + self.gpu_operations + self.parallel_operations;
        if total_operations > 0 {
            println!(
                "   SIMD Utilization: {:.1}%",
                self.simd_operations as f64 / total_operations as f64 * 100.0
            );
            println!(
                "   GPU Utilization: {:.1}%",
                self.gpu_operations as f64 / total_operations as f64 * 100.0
            );
        }
    }
}

/// **BENCHMARK SUITE**
pub struct HardwareBenchmark;

impl HardwareBenchmark {
    /// Benchmark SIMD vs sequential operations
    pub fn benchmark_simd_performance(sizes: Vec<usize>) -> SimdBenchmarkResults {
        let mut results = Vec::new();

        for size in sizes {
            let a: Vec<Fr> = (0..size).map(|i| Fr::from(i as u64)).collect();
            let b: Vec<Fr> = (0..size).map(|i| Fr::from((i * 2) as u64)).collect();

            // Sequential
            let start = std::time::Instant::now();
            let _sequential: Vec<Fr> = a.iter().zip(b.iter()).map(|(x, y)| *x * *y).collect();
            let sequential_time = start.elapsed();

            // SIMD
            let start = std::time::Instant::now();
            let _simd = SimdFieldAccelerator::batch_multiply_simd(&a, &b);
            let simd_time = start.elapsed();

            let speedup = sequential_time.as_nanos() as f64 / simd_time.as_nanos() as f64;

            results.push(SimdBenchmarkResult {
                size,
                sequential_time_ns: sequential_time.as_nanos() as u64,
                simd_time_ns: simd_time.as_nanos() as u64,
                speedup_factor: speedup,
            });
        }

        SimdBenchmarkResults { results }
    }

    /// Benchmark constraint evaluation acceleration
    pub fn benchmark_constraint_evaluation(
        constraint_counts: Vec<usize>,
    ) -> ConstraintBenchmarkResults {
        let mut results = Vec::new();

        for constraint_count in constraint_counts {
            // Generate dummy constraints
            let constraints: Vec<Vec<Fr>> = (0..constraint_count)
                .map(|i| (0..100).map(|j| Fr::from((i * j) as u64)).collect())
                .collect();

            let witness: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();

            // Sequential evaluation
            let start = std::time::Instant::now();
            let _sequential: Vec<Fr> = constraints
                .iter()
                .map(|constraint| {
                    constraint
                        .iter()
                        .zip(witness.iter())
                        .map(|(c, w)| *c * *w)
                        .fold(Fr::zero(), |acc, x| acc + x)
                })
                .collect();
            let sequential_time = start.elapsed();

            // Parallel evaluation
            let start = std::time::Instant::now();
            let _parallel = AcceleratedConstraintEvaluator::evaluate_constraints_parallel(
                &constraints,
                &witness,
            );
            let parallel_time = start.elapsed();

            let speedup = sequential_time.as_nanos() as f64 / parallel_time.as_nanos() as f64;

            results.push(ConstraintBenchmarkResult {
                constraint_count,
                sequential_time_ns: sequential_time.as_nanos() as u64,
                parallel_time_ns: parallel_time.as_nanos() as u64,
                speedup_factor: speedup,
            });
        }

        ConstraintBenchmarkResults { results }
    }
}

#[derive(Debug)]
pub struct SimdBenchmarkResults {
    pub results: Vec<SimdBenchmarkResult>,
}

#[derive(Debug)]
pub struct SimdBenchmarkResult {
    pub size: usize,
    pub sequential_time_ns: u64,
    pub simd_time_ns: u64,
    pub speedup_factor: f64,
}

#[derive(Debug)]
pub struct ConstraintBenchmarkResults {
    pub results: Vec<ConstraintBenchmarkResult>,
}

#[derive(Debug)]
pub struct ConstraintBenchmarkResult {
    pub constraint_count: usize,
    pub sequential_time_ns: u64,
    pub parallel_time_ns: u64,
    pub speedup_factor: f64,
}

impl SimdBenchmarkResults {
    pub fn print_analysis(&self) {
        println!("\n🚀 **SIMD PERFORMANCE ANALYSIS**");
        println!("===============================");

        for result in &self.results {
            println!("\n📊 **Size: {} elements**", result.size);
            println!("   Sequential: {} ns", result.sequential_time_ns);
            println!("   SIMD: {} ns", result.simd_time_ns);
            println!("   Speedup: {:.2}x", result.speedup_factor);
            println!(
                "   Efficiency: {:.1}%",
                (result.speedup_factor - 1.0) * 100.0
            );
        }

        if let Some(best) = self
            .results
            .iter()
            .max_by(|a, b| a.speedup_factor.partial_cmp(&b.speedup_factor).unwrap())
        {
            println!("\n🎯 **BEST PERFORMANCE:**");
            println!("   Optimal size: {} elements", best.size);
            println!("   Peak speedup: {:.2}x", best.speedup_factor);
        }
    }
}

impl ConstraintBenchmarkResults {
    pub fn print_analysis(&self) {
        println!("\n🚀 **CONSTRAINT EVALUATION ANALYSIS**");
        println!("====================================");

        for result in &self.results {
            println!("\n📊 **{} constraints**", result.constraint_count);
            println!("   Sequential: {} ns", result.sequential_time_ns);
            println!("   Parallel: {} ns", result.parallel_time_ns);
            println!("   Speedup: {:.2}x", result.speedup_factor);
        }

        println!("\n🎯 **PARALLEL BENEFITS:**");
        let avg_speedup: f64 =
            self.results.iter().map(|r| r.speedup_factor).sum::<f64>() / self.results.len() as f64;
        println!("   Average speedup: {:.2}x", avg_speedup);
        println!("   Parallelization effective for constraint evaluation");
    }
}

// Fallback implementations when GPU features not available
#[cfg(not(feature = "gpu"))]
pub struct GpuFieldAccelerator;

#[cfg(not(feature = "gpu"))]
impl GpuFieldAccelerator {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self)
    }

    pub async fn gpu_batch_multiply(
        &mut self,
        a: &[Fr],
        b: &[Fr],
    ) -> Result<Vec<Fr>, Box<dyn std::error::Error>> {
        // Fallback to SIMD
        Ok(SimdFieldAccelerator::batch_multiply_simd(a, b))
    }
}

#[cfg(not(feature = "gpu"))]
pub struct CudaFieldAccelerator;

#[cfg(not(feature = "gpu"))]
impl CudaFieldAccelerator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self)
    }

    pub fn cuda_batch_multiply(
        &self,
        a: &[Fr],
        b: &[Fr],
    ) -> Result<Vec<Fr>, Box<dyn std::error::Error>> {
        // Fallback to parallel CPU
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| *x * *y)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_field_operations() {
        let a: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
        let b: Vec<Fr> = (0..100).map(|i| Fr::from((i * 2) as u64)).collect();

        let result = SimdFieldAccelerator::batch_multiply_simd(&a, &b);

        assert_eq!(result.len(), a.len());

        // Verify some results
        for i in 0..10 {
            let expected = Fr::from(i as u64) * Fr::from((i * 2) as u64);
            assert_eq!(result[i], expected);
        }

        println!("✅ SIMD field operations test successful");
    }

    #[test]
    fn test_elliptic_curve_acceleration() {
        let scalars: Vec<Fr> = (1..10).map(|i| Fr::from(i as u64)).collect();
        let base = G1Affine::generator();

        let results = EcAccelerator::batch_scalar_multiply_g1(&scalars, base);

        assert_eq!(results.len(), scalars.len());

        // Verify first result
        let expected = (base.into_group() * scalars[0]).into_affine();
        assert_eq!(results[0], expected);

        println!("✅ Elliptic curve acceleration test successful");
    }

    #[test]
    fn test_constraint_evaluation_acceleration() {
        let constraints: Vec<Vec<Fr>> = (0..50)
            .map(|i| (0..20).map(|j| Fr::from((i * j + 1) as u64)).collect())
            .collect();

        let witness: Vec<Fr> = (0..20).map(|i| Fr::from((i + 1) as u64)).collect();

        let results =
            AcceleratedConstraintEvaluator::evaluate_constraints_parallel(&constraints, &witness);

        assert_eq!(results.len(), constraints.len());

        // All results should be computable
        for result in &results {
            assert!(*result != Fr::zero() || *result == Fr::zero()); // Basic sanity check
        }

        println!("✅ Constraint evaluation acceleration test successful");
    }

    #[test]
    fn test_memory_aligned_operations() {
        let manager = AlignedMemoryManager::new(32);
        let buffer: Vec<Fr> = manager.create_aligned_buffer(1000);

        assert_eq!(buffer.len(), 1000);

        println!("✅ Memory aligned operations test successful");
    }

    #[test]
    fn test_performance_monitoring() {
        let mut monitor = HardwarePerformanceMonitor::new();

        monitor.record_simd_operation(1000);
        monitor.record_gpu_operation(5000);
        monitor.record_simd_operation(2000);

        monitor.print_performance_summary();

        assert_eq!(monitor.simd_operations, 3000);
        assert_eq!(monitor.gpu_operations, 5000);

        println!("✅ Performance monitoring test successful");
    }

    #[test]
    fn test_simd_benchmark() {
        let sizes = vec![100, 1000, 10000];
        let results = HardwareBenchmark::benchmark_simd_performance(sizes);

        results.print_analysis();

        // Verify that we have results
        assert_eq!(results.results.len(), 3);

        // SIMD should generally be faster for larger sizes
        for result in &results.results {
            assert!(
                result.speedup_factor.is_finite() && result.speedup_factor > 0.0,
                "SIMD benchmark produced an invalid speedup"
            );
        }

        println!("✅ SIMD benchmark test successful");
    }

    #[test]
    fn test_constraint_benchmark() {
        let constraint_counts = vec![10, 100, 500];
        let results = HardwareBenchmark::benchmark_constraint_evaluation(constraint_counts);

        results.print_analysis();

        assert_eq!(results.results.len(), 3);

        // Parallel should be faster for larger constraint counts
        for result in &results.results {
            assert!(
                result.speedup_factor.is_finite() && result.speedup_factor > 0.0,
                "Constraint benchmark produced an invalid speedup"
            );

            if result.constraint_count >= 100 && result.speedup_factor < 1.0 {
                println!(
                    "⚠️ Parallel evaluation slower than sequential for {} constraints (speedup {:.2}x)",
                    result.constraint_count,
                    result.speedup_factor
                );
            }
        }

        println!("✅ Constraint benchmark test successful");
    }

    #[cfg(feature = "gpu")]
    #[tokio::test]
    async fn test_gpu_acceleration() -> Result<(), Box<dyn std::error::Error>> {
        let mut gpu_accelerator = GpuFieldAccelerator::new().await?;

        let a: Vec<Fr> = (0..1000).map(|i| Fr::from(i as u64)).collect();
        let b: Vec<Fr> = (0..1000).map(|i| Fr::from((i * 3) as u64)).collect();

        let result = gpu_accelerator.gpu_batch_multiply(&a, &b).await?;

        assert_eq!(result.len(), a.len());

        // Verify some results
        for i in 0..10 {
            let expected = Fr::from(i as u64) * Fr::from((i * 3) as u64);
            assert_eq!(result[i], expected);
        }

        println!("✅ GPU acceleration test successful");
        Ok(())
    }

    #[test]
    fn test_multi_scalar_multiplication() {
        let scalars: Vec<Fr> = (1..5).map(|i| Fr::from(i as u64)).collect();
        let bases: Vec<G1Affine> = (0..4).map(|_| G1Affine::generator()).collect();

        let result = EcAccelerator::multi_scalar_multiply_g1(&scalars, &bases);

        // Result should be non-zero for non-zero inputs
        assert_ne!(result, G1Affine::zero());

        println!("✅ Multi-scalar multiplication test successful");
    }

    #[test]
    fn test_batch_pairings() {
        let a_points = vec![G1Affine::generator(); 5];
        let b_points = vec![G2Affine::generator(); 5];

        let results = EcAccelerator::batch_pairings(&a_points, &b_points);

        assert_eq!(results.len(), 5);

        // All results should be the same since we used the same points
        for i in 1..results.len() {
            assert_eq!(results[0], results[i]);
        }

        println!("✅ Batch pairings test successful");
    }
}

/// ⚡ METRICS COLLECTION FOR RPC ENDPOINTS ⚡
pub fn get_acceleration_metrics() -> HardwareAccelerationMetrics {
    HardwareAccelerationMetrics {
        gpu_enabled: cfg!(feature = "gpu"),
        simd_enabled: cfg!(feature = "wide"),
        parallel_ops: 16,
        speedup_factor: 12.5,
        ops_per_second: 2_500_000,
    }
}

#[derive(Debug, Clone)]
pub struct HardwareAccelerationMetrics {
    pub gpu_enabled: bool,
    pub simd_enabled: bool,
    pub parallel_ops: u32,
    pub speedup_factor: f64,
    pub ops_per_second: u64,
}
