"""Command-line entry point; it intentionally does not expose unconstrained key search."""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import sys
import time
from pathlib import Path
from subprocess import run
from typing import TextIO

from keylab.backends import backend_info
from keylab.benchmarks import (
    available_scalar_backends,
    benchmark_ec,
    benchmark_hash160_only,
    benchmark_synthetic_wifs,
    benchmark_wif_file,
    benchmark_wif_to_pubkey,
)
from keylab.encoding.address import address_to_target_hash
from keylab.encoding.wif import decode as decode_wif
from keylab.encoding.wif import encode as encode_wif
from keylab.feature_audit import FEATURE_STATUS, feature_audit
from keylab.hashes.length_extension import sha256_length_extend
from keylab.hashes.llm_agents import plan_sha256_cube_bits
from keylab.hashes.reduced import (
    _sha_compress,
    invert_choice_words,
    invert_majority_word,
    ripemd160,
    ripemd160_reduced,
    sha256_backward_trace,
    sha256_forward_feed,
    sha256_reduced,
    sha256_reduced_stream,
    sha256_reverse_compress,
    sha256_schedule_dependencies,
    sha256_schedule_words,
)
from keylab.hashes.ripemd_cnf import ripemd160_preimage_cnf
from keylab.hashes.sha256_cnf import (
    sha256_compression_cnf,
    sha256_hash_preimage_cnf,
    sha256_secret_prefix_cnf,
)
from keylab.numtheory.core import euler_check, extended_gcd, fermat_check, totient
from keylab.numtheory.rsa import (
    batch_gcd,
    hastad_broadcast,
    pollard_rho_factor,
    rsa_exponentiation_roundtrip,
)
from keylab.sat.anf import MQCNFEncoder
from keylab.sat.backends import solve_cnf
from keylab.sat.diagnostics import write_formula_diagnostics
from keylab.sat.parallel import solve_parallel_cubes
from keylab.sat.solver import SOLVER_CANDIDATES, find_solver, run_solver


def _number_theory(args: argparse.Namespace) -> int:
    if args.operation == "gcd":
        gcd, x, y = extended_gcd(args.a, args.b)
        print(f"gcd={gcd} x={x} y={y}")
    elif args.operation == "totient":
        print(totient(args.n))
    elif args.operation == "fermat":
        print("passes" if fermat_check(args.a, args.n) else "fails")
    else:
        print("passes" if euler_check(args.a, args.n) else "fails")
    return 0


def _rsa_exponentiation(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        result = rsa_exponentiation_roundtrip(
            args.message,
            args.modulus,
            args.public_exponent,
            args.private_exponent,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "mode": "raw-textbook-rsa-roundtrip",
                "message": result.message,
                "ciphertext": result.ciphertext,
                "recovered_message": result.recovered_message,
                "success": result.success,
                "warning": (
                    "Educational arithmetic only. Raw RSA has no padding and is not "
                    "secure for real messages."
                ),
            },
            sort_keys=True,
        )
    )
    return 0 if result.success else 1


def _rsa_batch_gcd(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        findings = batch_gcd(args.modulus)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "mode": "rsa-pairwise-gcd-diagnostic",
                "findings": [
                    {
                        "first_index": finding.first_index,
                        "second_index": finding.second_index,
                        "common_divisor": finding.common_divisor,
                    }
                    for finding in findings
                ],
                "warning": "Educational diagnostic only; a common divisor may not be prime.",
            },
            sort_keys=True,
        )
    )
    return 0


def _rsa_pollard_rho(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        result = pollard_rho_factor(
            args.modulus,
            max_iterations=args.max_iterations,
            batch_size=args.batch_size,
            max_attempts=args.max_attempts,
            seed=args.seed,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "mode": "bounded-rsa-pollard-brent-factor-search",
                "factor": result.factor,
                "cofactor": result.cofactor,
                "success": result.success,
                "iterations": result.iterations,
                "attempts": result.attempts,
                "warning": (
                    "Educational bounded factor search; Pollard rho is not practical "
                    "for properly generated standard-size RSA moduli."
                ),
            },
            sort_keys=True,
        )
    )
    return 0 if result.success else 1


def _rsa_hastad_broadcast(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        message = hastad_broadcast(args.ciphertext, args.modulus, args.public_exponent)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "mode": "rsa-hastad-broadcast-toy-recovery",
                "message": message,
                "warning": (
                    "Applies only to repeated unpadded RSA messages with enough "
                    "pairwise-coprime moduli; use secure randomized padding for RSA."
                ),
            },
            sort_keys=True,
        )
    )
    return 0


def _sha256_majority_invert(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        result = invert_majority_word(args.output, args.a, args.b, args.c)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "mode": "sha256-majority-input-inversion",
                "recovered_word": f"0x{result.recovered_word:08x}",
                "determined_mask": f"0x{result.determined_mask:08x}",
                "ambiguous_mask": f"0x{result.ambiguous_mask:08x}",
                "fully_determined": result.fully_determined,
            },
            sort_keys=True,
        )
    )
    return 0


def _sha256_choice_invert(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        result = invert_choice_words(args.output, args.e, args.f, args.g)
    except ValueError as exc:
        parser.error(str(exc))
    recovered_inputs = {
        name: {
            "recovered_word": f"0x{operand.recovered_word:08x}",
            "determined_mask": f"0x{operand.determined_mask:08x}",
            "ambiguous_mask": f"0x{operand.ambiguous_mask:08x}",
            "fully_determined": operand.fully_determined,
        }
        for name, operand in (("e", result.e), ("f", result.f), ("g", result.g))
        if operand is not None
    }
    print(
        json.dumps(
            {
                "mode": "sha256-choice-input-inversion",
                "inputs": recovered_inputs,
                "fully_determined": result.fully_determined,
            },
            sort_keys=True,
        )
    )
    return 0


def _selftest() -> int:
    checks: list[tuple[str, bool]] = []
    gcd, x, y = extended_gcd(240, 46)
    checks.append(("extended gcd", gcd == 2 and 240 * x + 46 * y == gcd))
    checks.append(("totient", totient(36) == 12))
    rsa_modulus = 1009 * 1013
    rsa_phi = (1009 - 1) * (1013 - 1)
    rsa_public_exponent = pow(13, -1, rsa_phi)
    rsa_result = rsa_exponentiation_roundtrip(
        42,
        rsa_modulus,
        rsa_public_exponent,
        13,
    )
    checks.append(("toy RSA modular exponentiation round-trip", rsa_result.success))
    broadcast_moduli = (101, 103, 107)
    broadcast_message = 42
    broadcast_ciphertexts = tuple(
        pow(broadcast_message, 3, modulus) for modulus in broadcast_moduli
    )
    checks.append(
        (
            "toy RSA broadcast recovery",
            hastad_broadcast(broadcast_ciphertexts, broadcast_moduli, 3)
            == broadcast_message,
        )
    )
    majority_message = 0x12345678
    majority_result = invert_majority_word(
        majority_message,
        0xAAAAAAAA,
        0x55555555,
        None,
    )
    checks.append(
        (
            "SHA majority input inversion",
            majority_result.fully_determined
            and majority_result.recovered_word == majority_message,
        )
    )
    checks.append(("WIF round-trip", decode_wif(encode_wif(1)) == (bytes(31) + b"\x01", True, "mainnet")))
    checks.append(
        (
            "SHA-256 reference vector",
            hashlib.sha256(b"abc").hexdigest()
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
    )
    checks.append(
        (
            "RIPEMD-160 reference vector",
            ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        )
    )
    secret, known_message, suffix = b"test-key", b"message", b"&admin=true"
    original_tag = hashlib.sha256(secret + known_message).digest()
    extension = sha256_length_extend(
        original_tag,
        known_message,
        len(secret),
        suffix,
    )
    checks.append(
        (
            "SHA-256 length-extension reference",
            extension.forged_digest
            == hashlib.sha256(secret + extension.forged_message).digest(),
        )
    )
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'} {name}")
    return 0 if all(passed for _, passed in checks) else 1


def _sat_selftest(args: argparse.Namespace) -> int:
    satisfiable = "p cnf 1 1\n1 0\n"
    unsatisfiable = "p cnf 1 2\n1 0\n-1 0\n"
    detected = 0
    failures: list[str] = []
    for name in SOLVER_CANDIDATES:
        executable = find_solver((name,))
        if executable is None:
            continue
        detected += 1
        try:
            sat_result = run_solver(executable, satisfiable, timeout=args.timeout)
            unsat_result = run_solver(executable, unsatisfiable, timeout=args.timeout)
        except OSError as exc:
            failures.append(f"{name}: could not execute solver: {exc}")
            print(f"FAIL {name}: could not execute solver: {exc}")
            continue
        passed = sat_result.status == "SATISFIABLE" and unsat_result.status == "UNSATISFIABLE"
        print(
            f"{'PASS' if passed else 'FAIL'} {name} ({executable}): "
            f"SAT={sat_result.status}, UNSAT={unsat_result.status}"
        )
        if not passed:
            failures.append(name)

    if detected == 0:
        print("SKIP no supported SAT solver found on PATH")
        return 0
    return 1 if failures else 0


def _hex_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an even-length hexadecimal string") from exc


def _word32(value: str) -> int:
    try:
        word = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a decimal or 0x-prefixed 32-bit integer") from exc
    if not 0 <= word <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("must be a 32-bit unsigned integer")
    return word


def _fixed_bit(value: str) -> tuple[int, int]:
    try:
        index_text, bit_text = value.split("=", 1)
        index, bit = int(index_text), int(bit_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must have the form INDEX=0 or INDEX=1") from exc
    if index < 0 or bit not in (0, 1):
        raise argparse.ArgumentTypeError("must have the form INDEX=0 or INDEX=1")
    return index, bit


def _solver_version(executable: str) -> str:
    version = run([executable, "--version"], capture_output=True, text=True, timeout=5, check=False)
    output = version.stdout.strip() or version.stderr.strip()
    return output.splitlines()[0] if output else f"version unavailable (exit {version.returncode})"


def _candidate_matches_model(model, candidate: bytes) -> bool:
    if model.mode == "hash":
        return sha256_reduced(candidate, model.rounds) == model.target
    state = tuple(
        int.from_bytes(model.initial_state[offset : offset + 4], "big")
        for offset in range(0, 32, 4)
    )
    result = _sha_compress(candidate, state, model.rounds)
    return b"".join(word.to_bytes(4, "big") for word in result) == model.target


def _sha256_cnf(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.mode == "hash" and args.message_length is None:
        parser.error("--message-length is required for hash mode")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.cube_depth < 0:
        parser.error("--cube-depth must be nonnegative")
    if args.cube_depth and not args.solver:
        parser.error("--cube-depth requires --solver")
    if args.parallel_workers < 1:
        parser.error("--parallel-workers must be positive")
    fixed_bits: dict[int, int] = {}
    for index, value in args.fix_bit:
        if index in fixed_bits and fixed_bits[index] != value:
            parser.error(f"input bit {index} was fixed to conflicting values")
        fixed_bits[index] = value

    started = time.perf_counter()
    track_dag = args.track_dag or args.dag_output is not None
    try:
        if args.mode == "hash":
            model = sha256_hash_preimage_cnf(
                args.target,
                message_length=args.message_length,
                rounds=args.rounds,
                fixed_bits=fixed_bits,
                track_dag=track_dag,
                xor3_encoding=args.xor3_encoding,
            )
        else:
            model = sha256_compression_cnf(
                args.target,
                rounds=args.rounds,
                initial_state=args.initial_state,
                fixed_bits=fixed_bits,
                track_dag=track_dag,
                xor3_encoding=args.xor3_encoding,
            )
    except ValueError as exc:
        parser.error(str(exc))
    generation_seconds = time.perf_counter() - started

    if args.output == "-":
        output: TextIO = sys.stdout
        model.write_dimacs(output)
    else:
        with Path(args.output).open("w", encoding="ascii", newline="\n") as output_file:
            model.write_dimacs(output_file)

    metrics: dict[str, object] = {
        "mode": model.mode,
        "rounds": model.rounds,
        "message_length": model.message_length,
        "fixed_input_bits": len(model.fixed_bits),
        "variables": model.variable_count,
        "clauses": model.clause_count,
        "generation_seconds": generation_seconds,
        "dimacs_output": args.output,
        "solver": None,
    }
    if args.diagnostics_output:
        try:
            metrics["formula_diagnostics"] = write_formula_diagnostics(
                model.formula,
                args.diagnostics_output,
            )
        except OSError as exc:
            parser.error(f"could not write formula diagnostics: {exc}")
        metrics["diagnostics_output"] = args.diagnostics_output
    if track_dag:
        if model.formula.dag is None:
            parser.error("DAG tracking was requested but the model has no DAG")
        model.formula.dag.validate()
        metrics["dag_nodes"] = len(model.formula.dag.nodes)
        metrics["dag_tracked"] = True
        if args.dag_output:
            try:
                Path(args.dag_output).write_text(
                    model.formula.dag.to_json() + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
            except OSError as exc:
                parser.error(f"could not write DAG output: {exc}")
            metrics["dag_output"] = args.dag_output
    if args.solver:
        solver_version = _solver_version(args.solver)
        solver_started = time.perf_counter()
        if args.cube_depth:
            free_input_variables = tuple(
                variable
                for index, variable in enumerate(model.input_bits)
                if index not in model.fixed_bits
            )
            if args.cube_depth > len(free_input_variables):
                parser.error(
                    "--cube-depth cannot exceed the number of unfixed input bits "
                    f"({len(free_input_variables)})"
                )
            result = solve_parallel_cubes(
                args.solver,
                model.to_dimacs(),
                free_input_variables,
                depth=args.cube_depth,
                workers=args.parallel_workers,
                timeout=args.timeout,
            )
            metrics["cube_depth"] = args.cube_depth
            metrics["cube_total"] = result.total_cubes
            metrics["cube_completed"] = result.completed_cubes
            metrics["parallel_workers"] = args.parallel_workers
            assignments = result.assignments
            solver_return_code = None
        else:
            result = run_solver(args.solver, model.to_dimacs(), timeout=args.timeout)
            assignments = result.assignments
            solver_return_code = result.returncode
        solver_seconds = time.perf_counter() - solver_started
        metrics["solver"] = args.solver
        metrics["solver_version"] = solver_version
        metrics["solver_timeout_seconds"] = args.timeout
        metrics["solver_seconds"] = solver_seconds
        metrics["solver_status"] = result.status
        if solver_return_code is not None:
            metrics["solver_return_code"] = solver_return_code
        if result.status == "SATISFIABLE":
            candidate = model.recover_input(assignments)
            candidate_valid = _candidate_matches_model(model, candidate)
            metrics["candidate_validated"] = candidate_valid
            if candidate_valid:
                metrics["candidate_hex"] = candidate.hex()
    print(json.dumps(metrics, sort_keys=True), file=sys.stderr)
    return 1 if args.solver and result.status == "UNKNOWN" else 0


def _ripemd160_cnf(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.message_length is None:
        parser.error("--message-length is required")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    fixed_bits: dict[int, int] = {}
    for index, value in args.fix_bit:
        if index in fixed_bits and fixed_bits[index] != value:
            parser.error(f"input bit {index} was fixed to conflicting values")
        fixed_bits[index] = value

    started = time.perf_counter()
    try:
        model = ripemd160_preimage_cnf(
            args.target,
            message_length=args.message_length,
            steps=args.steps,
        )
        model.constrain_input_bits(fixed_bits)
    except ValueError as exc:
        parser.error(str(exc))
    generation_seconds = time.perf_counter() - started

    if args.output == "-":
        model.write_dimacs(sys.stdout)
    else:
        with Path(args.output).open("w", encoding="ascii", newline="\n") as output_file:
            model.write_dimacs(output_file)

    metrics: dict[str, object] = {
        "mode": "hash-preimage",
        "steps": model.steps,
        "message_length": model.message_length,
        "fixed_input_bits": len(model.fixed_bits),
        "variables": model.variable_count,
        "clauses": model.clause_count,
        "generation_seconds": generation_seconds,
        "dimacs_output": args.output,
        "solver": None,
    }
    if args.diagnostics_output:
        try:
            metrics["formula_diagnostics"] = write_formula_diagnostics(
                model.formula,
                args.diagnostics_output,
            )
        except OSError as exc:
            parser.error(f"could not write formula diagnostics: {exc}")
        metrics["diagnostics_output"] = args.diagnostics_output
    if args.solver:
        solver_version = _solver_version(args.solver)
        solver_started = time.perf_counter()
        result = run_solver(args.solver, model.to_dimacs(), timeout=args.timeout)
        metrics["solver"] = args.solver
        metrics["solver_version"] = solver_version
        metrics["solver_timeout_seconds"] = args.timeout
        metrics["solver_seconds"] = time.perf_counter() - solver_started
        metrics["solver_status"] = result.status
        metrics["solver_return_code"] = result.returncode
        if result.status == "SATISFIABLE":
            candidate = model.recover_input(result.assignments)
            candidate_valid = ripemd160_reduced(candidate, model.steps) == model.target
            metrics["candidate_validated"] = candidate_valid
            if candidate_valid:
                metrics["candidate_hex"] = candidate.hex()
    print(json.dumps(metrics, sort_keys=True), file=sys.stderr)
    return 1 if args.solver and result.status == "UNKNOWN" else 0


def _sha256_secret_prefix_cnf(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    started = time.perf_counter()
    track_dag = args.track_dag or args.dag_output is not None
    try:
        model = sha256_secret_prefix_cnf(
            args.target,
            known_message=args.message,
            secret_length=args.secret_length,
            rounds=args.rounds,
            track_dag=track_dag,
        )
    except ValueError as exc:
        parser.error(str(exc))
    generation_seconds = time.perf_counter() - started

    if args.output == "-":
        model.write_dimacs(sys.stdout)
    else:
        with Path(args.output).open("w", encoding="ascii", newline="\n") as output_file:
            model.write_dimacs(output_file)

    metrics: dict[str, object] = {
        "mode": "secret-prefix-hash",
        "rounds": model.rounds,
        "secret_length": args.secret_length,
        "known_message_length": len(args.message),
        "fixed_input_bits": len(model.fixed_bits),
        "variables": model.variable_count,
        "clauses": model.clause_count,
        "generation_seconds": generation_seconds,
        "dimacs_output": args.output,
        "solver": None,
        "warning": "Educational model only; use HMAC-SHA-256 for authentication.",
    }
    if track_dag:
        if model.model.formula.dag is None:
            parser.error("DAG tracking was requested but the model has no DAG")
        model.model.formula.dag.validate()
        metrics["dag_nodes"] = len(model.model.formula.dag.nodes)
        metrics["dag_tracked"] = True
        if args.dag_output:
            try:
                Path(args.dag_output).write_text(
                    model.model.formula.dag.to_json() + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
            except OSError as exc:
                parser.error(f"could not write DAG output: {exc}")
            metrics["dag_output"] = args.dag_output
    if args.solver:
        solver_version = _solver_version(args.solver)
        solver_started = time.perf_counter()
        result = run_solver(args.solver, model.to_dimacs(), timeout=args.timeout)
        metrics["solver"] = args.solver
        metrics["solver_version"] = solver_version
        metrics["solver_timeout_seconds"] = args.timeout
        metrics["solver_seconds"] = time.perf_counter() - solver_started
        metrics["solver_status"] = result.status
        metrics["solver_return_code"] = result.returncode
        if result.status == "SATISFIABLE":
            candidate = model.recover_secret(result.assignments)
            valid = sha256_reduced(candidate + args.message, model.rounds) == args.target
            metrics["candidate_validated"] = valid
            if valid:
                metrics["candidate_secret_hex"] = candidate.hex()
    print(json.dumps(metrics, sort_keys=True), file=sys.stderr)
    return 1 if args.solver and result.status == "UNKNOWN" else 0


def _sha256_cnf_benchmark(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if not 1 <= args.start_round <= args.end_round <= 64:
        parser.error("round range must satisfy 1 <= start-round <= end-round <= 64")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    solvers = args.solver if args.solver else [find_solver()]
    solvers = [solver for solver in solvers if solver is not None]
    xor3_encodings = (
        ("direct", "chain")
        if args.xor3_encoding == "both"
        else (args.xor3_encoding,)
    )
    known_message = b"keylab benchmark input"
    bit_constraints = {
        byte_index * 8 + bit_index: (byte >> (7 - bit_index)) & 1
        for byte_index, byte in enumerate(known_message)
        for bit_index in range(8)
    }
    rows: list[dict[str, object]] = []
    failed = False
    for rounds in range(args.start_round, args.end_round + 1):
        target = sha256_reduced(known_message, rounds=rounds)
        for xor3_encoding in xor3_encodings:
            generation_started = time.perf_counter()
            model = sha256_hash_preimage_cnf(
                target,
                message_length=len(known_message),
                rounds=rounds,
                xor3_encoding=xor3_encoding,
            )
            generation_seconds = time.perf_counter() - generation_started
            constraint_started = time.perf_counter()
            model.constrain_input_bits(bit_constraints)
            input_constraint_seconds = time.perf_counter() - constraint_started
            serialization_started = time.perf_counter()
            dimacs = model.to_dimacs()
            serialization_seconds = time.perf_counter() - serialization_started

            for solver in solvers or [None]:
                row: dict[str, object] = {
                    "benchmark": "sha256-cnf-known-input",
                    "hash": "sha256",
                    "rounds": rounds,
                    "xor3_encoding": xor3_encoding,
                    "schedule_expansion_words_per_block": max(0, rounds - 16),
                    "message_length": len(known_message),
                    "fixed_input_bits": len(model.fixed_bits),
                    "variables": model.variable_count,
                    "clauses": model.clause_count,
                    "generation_seconds": generation_seconds,
                    "input_constraint_seconds": input_constraint_seconds,
                    "dimacs_serialization_seconds": serialization_seconds,
                    "dimacs_bytes": len(dimacs.encode("ascii")),
                    "solver": solver,
                    "solver_seconds": None,
                    "solver_status": "NOT_FOUND" if solver is None else "UNKNOWN",
                    "candidate_validated": None,
                }
                if solver is not None:
                    solver_started = time.perf_counter()
                    result = run_solver(solver, dimacs, timeout=args.timeout)
                    row["solver_seconds"] = time.perf_counter() - solver_started
                    row["solver_status"] = result.status
                    if result.status == "SATISFIABLE":
                        candidate = model.recover_input(result.assignments)
                        row["candidate_validated"] = (
                            candidate == known_message
                            and sha256_reduced(candidate, rounds) == target
                        )
                    if (
                        result.status != "SATISFIABLE"
                        or row["candidate_validated"] is not True
                    ):
                        failed = True
                rows.append(row)
                print(json.dumps(row, sort_keys=True))

    if args.csv_output:
        fields: list[str] = [
            "benchmark",
            "hash",
            "rounds",
            "message_length",
            "fixed_input_bits",
            "xor3_encoding",
            "variables",
            "clauses",
            "generation_seconds",
            "input_constraint_seconds",
            "dimacs_serialization_seconds",
            "dimacs_bytes",
            "solver_seconds",
            "solver",
            "solver_status",
            "candidate_validated",
            "schedule_expansion_words_per_block",
        ]
        try:
            with Path(args.csv_output).open("w", encoding="utf-8", newline="") as output_file:
                writer = csv.DictWriter(output_file, fieldnames=fields)
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
        except OSError as exc:
            parser.error(f"could not write benchmark CSV: {exc}")
    return 1 if failed else 0


def _sat_throughput_benchmark(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from keylab.sat.benchmark_throughput import benchmark_solving_throughput

    try:
        benchmark_solving_throughput(
            hash_name=args.hash_name,
            rounds=args.rounds,
            cube_depth=args.cube_depth,
            worker_counts=args.workers,
            timeout_per_cube=args.timeout_per_cube,
            solver=args.solver,
            csv_output=args.csv_output,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


def _sha256_agent_solve(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Use LLM-planned cube-variable ordering with local SAT and hash verification."""
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.parallel_workers < 1:
        parser.error("--parallel-workers must be positive")
    fixed_bits: dict[int, int] = {}
    for index, value in args.fix_bit:
        if index in fixed_bits and fixed_bits[index] != value:
            parser.error(f"input bit {index} was fixed to conflicting values")
        fixed_bits[index] = value
    try:
        model = sha256_hash_preimage_cnf(
            args.target,
            message_length=args.message_length,
            rounds=args.rounds,
            fixed_bits=fixed_bits,
        )
        agent_plan = plan_sha256_cube_bits(
            rounds=args.rounds,
            message_length=args.message_length,
            input_bit_count=len(model.input_bits),
            clause_count=model.clause_count,
            variable_count=model.variable_count,
            depth=args.cube_depth,
            fixed_bit_indices=set(model.fixed_bits),
            model=args.agent_model,
        )
    except (ImportError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))

    available = tuple(
        variable for index, variable in enumerate(model.input_bits) if index not in model.fixed_bits
    )
    selected_variables = tuple(model.input_bits[index] for index in agent_plan.bit_indices)
    selected = set(selected_variables)
    variable_order = selected_variables + tuple(variable for variable in available if variable not in selected)
    result = solve_parallel_cubes(
        args.solver,
        model.to_dimacs(),
        variable_order,
        depth=args.cube_depth,
        workers=args.parallel_workers,
        timeout=args.timeout,
    )
    output: dict[str, object] = {
        "status": result.status,
        "rounds": args.rounds,
        "message_length": args.message_length,
        "cube_depth": result.cube_depth,
        "cube_total": result.total_cubes,
        "cube_completed": result.completed_cubes,
        "agent_model": args.agent_model,
        "agent_bit_indices": list(agent_plan.bit_indices),
        "agent_suggestions": {role: list(bits) for role, bits in agent_plan.agent_suggestions.items()},
        "agent_warnings": list(agent_plan.warnings),
        "verified": False,
    }
    if result.status == "SATISFIABLE":
        candidate = model.recover_input(result.assignments)
        verified = sha256_reduced(candidate, args.rounds) == args.target
        output["verified"] = verified
        if verified:
            output["candidate_hex"] = candidate.hex()
        else:
            output["verification_error"] = "SAT assignment did not reproduce the target digest"
    print(json.dumps(output, indent=2, sort_keys=True))
    return 1 if result.status == "UNKNOWN" or output["verified"] is False and result.status == "SATISFIABLE" else 0


def _hash_cnf_selftest(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    message = args.message
    solver = args.solver if args.solver is not None else find_solver()
    failed = False

    for rounds in args.rounds:
        try:
            if args.hash_name == "sha256":
                target = sha256_reduced(message, rounds=rounds)
                model = sha256_hash_preimage_cnf(
                    target,
                    message_length=len(message),
                    rounds=rounds,
                    fixed_bits={
                        byte_index * 8 + bit_index: (byte >> (7 - bit_index)) & 1
                        for byte_index, byte in enumerate(message)
                        for bit_index in range(8)
                    },
                )
            else:
                target = ripemd160_reduced(message, steps=rounds)
                model = ripemd160_preimage_cnf(
                    target,
                    message_length=len(message),
                    steps=rounds,
                )
                model.constrain_input_bits(
                    {
                        byte_index * 8 + bit_index: (byte >> (7 - bit_index)) & 1
                        for byte_index, byte in enumerate(message)
                        for bit_index in range(8)
                    }
                )
        except ValueError as exc:
            parser.error(str(exc))

        row: dict[str, object] = {
            "test": "reduced-round-cnf-known-input",
            "hash": args.hash_name,
            "rounds": rounds,
            "message_length": len(message),
            "fixed_input_bits": len(model.fixed_bits),
            "variables": model.variable_count,
            "clauses": model.clause_count,
            "target": target.hex(),
            "solver": solver,
        }
        if solver is None:
            row["status"] = "CNF_GENERATED_SOLVER_NOT_FOUND"
        else:
            try:
                result = run_solver(solver, model.to_dimacs(), timeout=args.timeout)
            except OSError as exc:
                parser.error(f"could not execute SAT solver: {exc}")
            row["solver_status"] = result.status
            if result.status == "SATISFIABLE":
                candidate = model.recover_input(result.assignments)
                candidate_digest = (
                    sha256_reduced(candidate, rounds)
                    if args.hash_name == "sha256"
                    else ripemd160_reduced(candidate, steps=rounds)
                )
                validated = candidate == message and candidate_digest == target
                row["candidate_validated"] = validated
                if not validated:
                    failed = True
            else:
                failed = True
        print(json.dumps(row, sort_keys=True))

    return 1 if failed else 0


def _sha256_length_extension(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        result = sha256_length_extend(
            args.tag,
            args.message,
            args.secret_length,
            args.suffix,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "warning": "Educational demo only; secret-prefix SHA-256 is not a secure MAC.",
                "glue_padding_hex": result.glue_padding.hex(),
                "forged_message_hex": result.forged_message.hex(),
                "forged_digest_hex": result.forged_digest.hex(),
            },
            sort_keys=True,
        )
    )
    return 0


def _sha256_backward_ledger(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if not 0 <= args.message_length <= 55:
        parser.error("--message-length must be between 0 and 55 for a single padded block")
    try:
        trace = sha256_backward_trace(args.target, rounds=args.rounds)
    except ValueError as exc:
        parser.error(str(exc))
    block_reverse_report: dict[str, object] | None = None
    if args.reverse_to_round is not None:
        if args.block is None:
            parser.error("--reverse-to-round requires --block with the exact 64-byte padded block")
        if len(args.target) != 32:
            parser.error("--target must be exactly 32 bytes")
        if not 0 <= args.reverse_to_round <= args.rounds:
            parser.error("--reverse-to-round must be between 0 and --rounds")
        output_state = tuple(
            int.from_bytes(args.target[offset : offset + 4], "big")
            for offset in range(0, 32, 4)
        )
        try:
            exact_trace = sha256_reverse_compress(
                output_state, args.block, rounds=args.rounds
            )
        except ValueError as exc:
            parser.error(f"known block forward-feed verification failed: {exc}")
        boundary_state = exact_trace.working_states[args.reverse_to_round]
        block_reverse_report = {
            "forward_feed_verified": True,
            "block_hex": args.block.hex(),
            "state_after_round": args.reverse_to_round,
            "state_words": [f"{word:08x}" for word in boundary_state],
            "round_numbering": "state_after_round 0 is the initial chaining state; 32 is after rounds 0..31",
        }
    schedule_nodes = sha256_schedule_dependencies(args.rounds)
    schedule_analysis: dict[str, object] = {
        "word_count": len(schedule_nodes),
        "word_dependencies": [
            {
                "word": f"W{node.word_index}",
                "operation": node.operation,
                "dependencies": node.dependencies,
            }
            for node in schedule_nodes
        ],
    }
    if args.known_message is not None:
        if len(args.known_message) != args.message_length:
            parser.error("--known-message byte length must match --message-length")
        padded = args.known_message + b"\x80"
        padded += b"\0" * (56 - len(padded))
        padded += (len(args.known_message) * 8).to_bytes(8, "big")
        schedule_values = sha256_schedule_words(padded)
        observed_digest = sha256_reduced(args.known_message, rounds=args.rounds)
        schedule_analysis["known_message_hex"] = args.known_message.hex()
        schedule_analysis["known_message_target_matches"] = observed_digest == args.target
        schedule_analysis["evaluated_words"] = {
            f"W{index}": f"{value:08x}" for index, value in enumerate(schedule_values)
        }
        schedule_analysis["padded_block_hex"] = padded.hex()
        bridge_analysis: dict[str, object] = {
            "known_message_word": f"W{trace.bridge_w_index}",
            "known_message_target_matches": observed_digest == args.target,
            "known_message_word_value": (
                f"{schedule_values[trace.bridge_w_index]:08x}"
                if observed_digest == args.target
                else None
            ),
            "derived_state_values": None,
        }
        if observed_digest == args.target:
            known_bridge_word = schedule_values[trace.bridge_w_index]
            bridge_analysis["derived_state_values"] = {
                f"h{trace.bridge_h_index}": (
                    trace.bridge_h_offset - known_bridge_word
                )
                & 0xFFFFFFFF
            }
    else:
        schedule_analysis["evaluated_words"] = None
        schedule_analysis["padded_block_hex"] = None
        bridge_analysis = {
            "known_message_word": f"W{trace.bridge_w_index}",
            "known_message_target_matches": None,
            "known_message_word_value": None,
            "derived_state_values": None,
        }

    state_names = ("a", "b", "c", "d", "e", "f", "g", "h")
    known_a_words = {f"a{index}": f"{value:08x}" for index, value in trace.known_a_values}
    output = {
        "analysis": "numeric SHA-256 backward trace only; no preimage search is performed",
        "assumption": "target is a one-block SHA-256-shaped digest using the standard IV",
        "verdict": "experimental algebraic evidence, not a SHA-256 break",
        "target_provenance": "caller-supplied; not independently tied to a known message",
        "message_length": args.message_length,
        "rounds": args.rounds,
        "target": args.target.hex(),
        "schedule_dependency_graph": schedule_analysis,
        "working_state_after_feed_forward_removal": {
            f"{name}{args.rounds}": f"{value:08x}"
            for name, value in zip(state_names, trace.working_state)
        },
        "numerically_recovered_a_words": known_a_words,
        "reverse_steps": [
            {
                "round": step.round_index,
                "t1": f"{step.t1:08x}",
                "t2": f"{step.t2:08x}",
                "recovered_a": f"a{step.recovered_a_index}",
                "value": f"{step.recovered_a:08x}",
            }
            for step in trace.steps
        ],
        "first_unresolved_boundary": {
            "round": trace.boundary_round,
            "equation": (
                f"a{trace.boundary_a_index} = "
                f"e{trace.boundary_round + 1} - "
                f"T1_{trace.boundary_round} (mod 2**32)"
            ),
            "known_t1": f"{trace.boundary_t1:08x}",
            "unresolved": (
                f"e{trace.boundary_round + 1} is not determined by the final "
                "digest state alone"
            ),
        },
        "two_line_underdetermination": {
            "description": (
                "The backward A-state boundary and the final-round H/W relation are "
                "reported separately; this trace does not establish a direct W63-to-e60 "
                "identity."
            ),
            "round": trace.bridge_round,
            "a_line_boundary_equation": (
                f"a{trace.boundary_a_index} = e{trace.boundary_round + 1} - "
                f"T1_{trace.boundary_round} (mod 2**32), "
                f"T1_{trace.boundary_round}=0x{trace.boundary_t1:08x}"
            ),
            "final_round_h_line_equation": (
                f"h{trace.bridge_h_index} = "
                f"0x{trace.bridge_h_offset:08x} - "
                f"W{trace.bridge_w_index} (mod 2**32)"
            ),
            "interpretation": (
                "These are distinct local equations, not a shared 32-bit parameterization "
                "or global rank result. The schedule equations constrain W63; the supplied "
                "e60 = constant - W63 relation is not derived by this trace."
            ),
            "known_message_check": bridge_analysis,
        },
        "round_boundary_dependencies": {
            "a_boundary_identity": (
                f"e{trace.boundary_round + 1} = "
                f"a{trace.boundary_a_index} + T1_{trace.boundary_round} "
                "(mod 2**32)"
            ),
            "T1_round_expression": (
                f"T1_{trace.boundary_round} = h{trace.boundary_round} + "
                f"Sigma1(e{trace.boundary_round}) + "
                f"Ch(e{trace.boundary_round},f{trace.boundary_round},"
                f"g{trace.boundary_round}) + K{trace.boundary_round} + "
                f"W{trace.boundary_round} (mod 2**32)"
            ),
            "round_expression_unresolved_inputs": [
                f"h{trace.boundary_round}",
                f"e{trace.boundary_round}",
                f"f{trace.boundary_round}",
                f"g{trace.boundary_round}",
                f"W{trace.boundary_round}",
            ],
            "warning": (
                "The message-schedule DAG does not establish an algebraic "
                "dependency between W63 and e60; that requires the missing "
                "external equations/artifacts."
            ),
        },
        "state_classification": {
            "numerically_recovered": {
                **{
                    f"{name}{args.rounds}": f"{value:08x}"
                    for name, value in zip(state_names, trace.working_state)
                },
                **known_a_words,
            },
            "symbolically_determined": [
                {
                    "variable": f"a{trace.boundary_a_index}",
                    "equation": (
                        f"a{trace.boundary_a_index} = "
                        f"e{trace.boundary_round + 1} - "
                        f"T1_{trace.boundary_round} (mod 2**32)"
                    ),
                    "known_t1": f"{trace.boundary_t1:08x}",
                }
            ],
            "still_unresolved": [
                f"e{trace.boundary_round + 1}",
                f"a{trace.boundary_a_index}",
                "message words and the candidate preimage",
            ],
        },
        "interpretation": {
            "claim": (
                "The state-shift relations and four reverse A-word steps are "
                "numerically consistent with the supplied digest and standard IV."
            ),
            "not_established": [
                "that the supplied digest came from a particular candidate message",
                "uniqueness or degree-of-freedom count of any algebraic system",
                "that the symbolic boundary is an irreducible obstruction",
                "that timeout or SAT/UNSAT behavior proves full-round security or a break",
            ],
            "external_stage4_artifacts_loaded": False,
            "reported_stage4_timeout": {
                "status": "UNKNOWN",
                "reported_seconds": 3600.21,
                "reported_threads": 4,
                "reported_variables": 100768,
                "reported_constraints": 211600,
                "reported_native_xor_rows": 47586,
                "provenance": "user-supplied transcript; not independently reproduced here",
                "diagnosis": (
                    "A timeout alone does not identify the cause or imply UNSAT. "
                    "Solver conflict/decision/propagation logs and the exact equation artifact "
                    "are needed for causal analysis."
                ),
            },
        },
        "candidate_recovered": False,
    }
    if block_reverse_report is not None:
        output["known_block_round_boundary"] = block_reverse_report
    serialized = json.dumps(output, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(serialized)
    else:
        try:
            Path(args.output).write_text(serialized, encoding="utf-8")
        except OSError as exc:
            parser.error(f"could not write backward ledger: {exc}")
        print(f"Backward trace written to {args.output}", file=sys.stderr)
    return 0


def _address_hash(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        target_hash = address_to_target_hash(args.address)
    except ValueError as exc:
        parser.error(str(exc))
    print(target_hash.hex())
    return 0


def _wif_derive(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Derive address formats from an interactive WIF, with private output opt-in."""
    from keylab.encoding.address import derive_addresses_from_wif

    wif = args.wif if args.wif is not None else getpass.getpass("WIF (input hidden): ")
    try:
        result = derive_addresses_from_wif(wif, reveal_private=args.show_private)
    except (TypeError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    if args.show_private:
        result["notice"] = "Private key hex included by explicit request; do not save or share this output."
    if args.show_wif:
        result["wif"] = wif
    print(json.dumps(result, sort_keys=True))
    return 0


def _sha256_symbolic_roundtrip(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Solve a tiny free-input SHA model and independently verify the candidate."""
    if not 1 <= args.rounds <= 64:
        parser.error("--rounds must be between 1 and 64")
    if len(args.message) > 55:
        parser.error("--message must be at most 55 bytes for this one-block symbolic check")
    from keylab.hashes.reduced import sha256_reduced
    from keylab.hashes.sha256_cnf import sha256_hash_preimage_cnf

    target = sha256_reduced(args.message, rounds=args.rounds)
    try:
        model = sha256_hash_preimage_cnf(
            target,
            message_length=len(args.message),
            rounds=args.rounds,
            xor3_encoding=args.xor3_encoding,
        )
        result = solve_cnf(
            model.formula.clauses,
            backend=args.backend,
            solver_name=args.solver_name,
        )
    except (ImportError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    report: dict[str, object] = {
        "mode": "sha256-symbolic-roundtrip",
        "rounds": args.rounds,
        "message_length": len(args.message),
        "variables": model.variable_count,
        "clauses": model.clause_count,
        "backend": result.backend,
        "solver_status": result.status,
    }
    if result.status == "SATISFIABLE":
        candidate = model.recover_input(result.assignments)
        report["candidate_hex"] = candidate.hex()
        report["target_verified"] = sha256_reduced(candidate, args.rounds) == target
        report["matches_fixture"] = candidate == args.message
    else:
        report["target_verified"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if result.status == "SATISFIABLE" and report["target_verified"] else 1


def _sha256_stream(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        if args.input == "-":
            digest = sha256_reduced_stream(sys.stdin.buffer, rounds=args.rounds)
        else:
            with Path(args.input).open("rb") as input_file:
                digest = sha256_reduced_stream(input_file, rounds=args.rounds)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    print(digest.hex())
    return 0


def _sha256_reverse_compress_cli(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if len(args.output_state) != 32:
        parser.error("--output-state must be exactly 32 bytes (64 hex characters)")
    if len(args.initial_state) != 32:
        parser.error("--initial-state must be exactly 32 bytes (64 hex characters)")
    output_state = tuple(
        int.from_bytes(args.output_state[offset : offset + 4], "big")
        for offset in range(0, 32, 4)
    )
    initial_state = tuple(
        int.from_bytes(args.initial_state[offset : offset + 4], "big")
        for offset in range(0, 32, 4)
    )
    try:
        trace = sha256_reverse_compress(
            output_state,
            args.block,
            rounds=args.rounds,
            initial_state=initial_state,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "rounds": trace.rounds,
                "initial_state_verified": True,
                "output_state_hex": args.output_state.hex(),
                "working_states": [
                    [f"{word:08x}" for word in state] for state in trace.working_states
                ],
            },
            sort_keys=True,
        )
    )
    return 0


def _sha256_forward_feed_cli(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        trace = sha256_forward_feed(args.prefix_block, args.suffix)
    except (ValueError, ArithmeticError) as exc:
        parser.error(str(exc))
    target_matches = None if args.target is None else trace.digest == args.target
    print(
        json.dumps(
            {
                "prefix_block_bits": len(args.prefix_block) * 8,
                "prefix_block_hex": args.prefix_block.hex(),
                "suffix_hex": args.suffix.hex(),
                "prefix_chaining_state": [f"{word:08x}" for word in trace.prefix_state],
                "padded_suffix_blocks_hex": [block.hex() for block in trace.padded_suffix_blocks],
                "digest_hex": trace.digest.hex(),
                "forward_feed_verified_against_hashlib": trace.verified_against_hashlib,
                "target_matches": target_matches,
            },
            sort_keys=True,
        )
    )
    return 0 if target_matches is not False else 1


def _mq_cnf(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        with Path(args.equations).open(encoding="utf-8") as input_file:
            payload = json.load(input_file)
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"could not read MQ equation JSON: {exc}")

    if not isinstance(payload, dict) or set(payload) != {"num_variables", "equations"}:
        parser.error("MQ JSON must contain exactly 'num_variables' and 'equations'")
    num_variables = payload["num_variables"]
    equations = payload["equations"]
    if type(num_variables) is not int or num_variables < 0:
        parser.error("'num_variables' must be a nonnegative integer")
    if not isinstance(equations, list):
        parser.error("'equations' must be a list")

    encoder = MQCNFEncoder(num_variables)
    try:
        for index, equation in enumerate(equations):
            if not isinstance(equation, dict) or set(equation) != {
                "quadratic_terms",
                "linear_terms",
                "rhs",
            }:
                raise ValueError(
                    f"equation {index} must contain exactly quadratic_terms, "
                    "linear_terms, and rhs"
                )
            quadratic_terms = equation["quadratic_terms"]
            linear_terms = equation["linear_terms"]
            if not isinstance(quadratic_terms, list) or not isinstance(linear_terms, list):
                raise TypeError(f"equation {index} terms must be lists")
            normalized_quadratic: list[tuple[int, int]] = []
            for term in quadratic_terms:
                if (
                    not isinstance(term, list)
                    or len(term) != 2
                    or any(type(variable) is not int for variable in term)
                ):
                    raise TypeError(
                        f"quadratic terms in equation {index} must be two-integer lists"
                    )
                normalized_quadratic.append((term[0], term[1]))
            if any(type(variable) is not int for variable in linear_terms):
                raise TypeError(f"linear terms in equation {index} must be integer indices")
            encoder.add_equation(
                normalized_quadratic,
                linear_terms,
                equation["rhs"],
            )
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))

    if args.output == "-":
        encoder.formula.write_dimacs(sys.stdout)
    else:
        try:
            with Path(args.output).open("w", encoding="ascii", newline="\n") as output_file:
                encoder.formula.write_dimacs(output_file)
        except OSError as exc:
            parser.error(f"could not write DIMACS output: {exc}")

    print(
        json.dumps(
            {
                "mode": "mq-anf-to-cnf",
                "input_variables": num_variables,
                "equations": encoder.equation_count,
                "quadratic_products": len(encoder.product_variables),
                "variables": encoder.formula.variable_count,
                "clauses": len(encoder.formula.clauses),
                "encoding": "ordinary DIMACS CNF with Tseitin AND/XOR gates",
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 0


def _backend_status() -> int:
    """Print installed optional backends and SAT dispatch candidates."""
    from keylab.sat.backends import available_backends

    print(json.dumps({"backends": backend_info(), "sat_dispatch_order": available_backends()}, sort_keys=True))
    return 0


def _feature_audit() -> int:
    """Print source/test-file evidence without overstating executed checks."""
    print(json.dumps({"audit": feature_audit(), "feature_status": FEATURE_STATUS}, indent=2, sort_keys=True))
    return 0


def _benchmark_pubkey(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    backends = available_scalar_backends() if args.backend == "all" else (args.backend,)
    if not backends:
        parser.error("--backend all found no usable scalar multiplication backends")
    reports = []
    for backend in backends:
        try:
            reports.append(benchmark_wif_to_pubkey(args.iterations, warmup=args.warmup, backend=backend))
        except (ImportError, OSError, ValueError, ArithmeticError) as exc:
            parser.error(f"benchmark failed for backend {backend}: {exc}")
    print(json.dumps({"benchmark": "wif-to-compressed-pubkey", "reports": reports}, sort_keys=True))
    return 0


def _benchmark_ec(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Compare Python, v65-windowed, and available native ECC backends."""
    try:
        report = benchmark_ec(
            count=args.count,
            seed=args.seed,
            repetitions=args.repetitions,
            backend=args.backend,
        )
    except (ImportError, OSError, ValueError, ArithmeticError) as exc:
        parser.error(f"ECC benchmark failed: {exc}")
    print(
        f"secp256k1 G multiplication | scalars={report['count']} | seed={report['seed']} | "
        f"repetitions={report['repetitions']} | statistic=median"
    )
    print(f"{'Method':<24} {'keys/sec':>12} {'median ms/corpus':>19}")
    print("-" * 58)
    for row in report["methods"]:
        print(
            f"{row['method']:<24} {row['median_keys_per_second']:>12.1f} "
            f"{row['median_ms_per_corpus']:>19.3f}"
        )
    print(f"v65 table setup (excluded): {report['v65_table_setup_ms_excluded']:.3f} ms")
    print("Correctness: every method matched the Python reference on the shared scalar corpus.")
    print(report["note"])
    return 0


def _benchmark_wifs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Benchmark a random synthetic corpus or WIFs loaded from a local file."""
    backends = available_scalar_backends() if args.backend == "all" else (args.backend,)
    reports = []
    for backend in backends:
        try:
            if args.wif_file:
                report = benchmark_wif_file(
                    args.wif_file,
                    backend=backend,
                    derive_addresses=not args.no_addresses,
                    address_types=args.addresses,
                    warmup=args.warmup,
                    repetitions=args.repetitions,
                )
            else:
                report = benchmark_synthetic_wifs(
                    args.count,
                    backend=backend,
                    derive_addresses=not args.no_addresses,
                    address_types=args.addresses,
                    warmup=args.warmup,
                    repetitions=args.repetitions,
                )
        except (ImportError, OSError, ValueError, ArithmeticError) as exc:
            parser.error(f"multi-WIF benchmark failed for backend {backend}: {exc}")
        reports.append(report)
    print(json.dumps({"reports": reports}, sort_keys=True))
    return 0


def _benchmark_hash160(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        report = benchmark_hash160_only(args.count, backend=args.backend)
    except (ImportError, OSError, ValueError, ArithmeticError) as exc:
        parser.error(f"HASH160 benchmark failed: {exc}")
    print(json.dumps(report, sort_keys=True))
    return 0


def _sat_solve(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Read DIMACS CNF and solve it through the selected native SAT binding."""
    try:
        text = Path(args.input).read_text(encoding="ascii")
    except OSError as exc:
        parser.error(f"could not read DIMACS input: {exc}")

    variable_count = None
    expected_clauses = None
    tokens: list[int] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("c"):
            continue
        if stripped.startswith("p "):
            header = stripped.split()
            if len(header) != 4 or header[1] != "cnf":
                parser.error("DIMACS header must have the form 'p cnf VARIABLES CLAUSES'")
            try:
                variable_count, expected_clauses = int(header[2]), int(header[3])
            except ValueError:
                parser.error("DIMACS header counts must be integers")
            continue
        try:
            tokens.extend(int(token) for token in stripped.split())
        except ValueError:
            parser.error("DIMACS clause data must contain integer literals")
    if variable_count is None or expected_clauses is None:
        parser.error("DIMACS input must contain a problem header")
    if variable_count < 0 or expected_clauses < 0:
        parser.error("DIMACS header counts must be nonnegative")
    if tokens and tokens[-1] != 0:
        parser.error("DIMACS input ends with an unterminated clause")

    clauses: list[list[int]] = []
    current: list[int] = []
    for literal in tokens:
        if literal == 0:
            clauses.append(current)
            current = []
        else:
            if abs(literal) > variable_count:
                parser.error("DIMACS clause references a variable outside the declared range")
            current.append(literal)
    if len(clauses) != expected_clauses:
        parser.error("DIMACS clause count does not match the header")

    try:
        result = solve_cnf(clauses, backend=args.backend, solver_name=args.solver_name)
    except (RuntimeError, ValueError, ImportError) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "status": result.status,
                "backend": result.backend,
                "elapsed_seconds": result.elapsed_seconds,
                "assignments": result.assignments,
            },
            sort_keys=True,
        )
    )
    return 0 if result.status != "UNKNOWN" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keylab", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("backends", help="list installed optional crypto, math, and SAT backends")
    commands.add_parser(
        "audit", aliases=("feature-audit",), help="report implemented features and available evidence files"
    )
    pubkey_benchmark = commands.add_parser(
        "benchmark-pubkey",
        help="measure WIF decode, scalar multiplication, and compressed public-key formatting",
    )
    pubkey_benchmark.add_argument("--iterations", "--count", dest="iterations", type=int, default=1_000)
    pubkey_benchmark.add_argument("--warmup", type=int, default=20)
    pubkey_benchmark.add_argument(
        "--backend", choices=("auto", "python", "python-affine-window", "python-glv", "python-wnaf", "coincurve", "fastecdsa", "all"), default="auto"
    )
    ec_benchmark = commands.add_parser(
        "benchmark-ec",
        help="compare secp256k1 generator multiplication on a reproducible scalar corpus",
    )
    ec_benchmark.add_argument("--count", type=int, default=12, help="number of deterministic test scalars")
    ec_benchmark.add_argument("--seed", type=int, default=20261020, help="seed for the public benchmark corpus")
    ec_benchmark.add_argument("--repetitions", type=int, default=5, help="timed repetitions; median is reported")
    ec_benchmark.add_argument(
        "--backend",
        choices=("all", "python", "python-affine-window", "python-glv", "python-wnaf", "v65-windowed", "coincurve", "fastecdsa"),
        default="all",
    )
    wif_benchmark = commands.add_parser(
        "benchmark-wifs",
        help="benchmark many synthetic WIFs or a local newline-delimited WIF corpus",
        description="Reports stage timings only; it never prints WIFs, scalars, public keys, or derived addresses.",
    )
    wif_benchmark.add_argument("--count", type=int, default=1_000, help="synthetic WIF count (1..1,000,000)")
    wif_benchmark.add_argument("--wif-file", help="text file with one WIF per line; blank lines and # comments are ignored")
    wif_benchmark.add_argument("--warmup", type=int, default=3)
    wif_benchmark.add_argument("--repetitions", type=int, default=5, help="repeat the same corpus and report median timings")
    wif_benchmark.add_argument("--backend", choices=("auto", "python", "python-affine-window", "python-glv", "python-wnaf", "coincurve", "fastecdsa", "all"), default="auto")
    wif_benchmark.add_argument(
        "--addresses",
        nargs="+",
        choices=("p2pkh", "p2sh_p2wpkh", "p2wpkh", "p2tr"),
        help="address types to time (default: all types supported by each WIF)",
    )
    wif_benchmark.add_argument("--no-addresses", action="store_true", help="measure only through public-key serialization")
    hash160_benchmark = commands.add_parser(
        "benchmark-hash160",
        help="measure HASH160 throughput on unique compressed public-key fixtures",
    )
    hash160_benchmark.add_argument("--count", type=int, default=10_000)
    hash160_benchmark.add_argument(
        "--backend",
        choices=("auto", "python", "python-affine-window", "python-glv", "python-wnaf", "coincurve", "fastecdsa"),
        default="auto",
        help="backend used to precompute valid public-key fixtures; excluded from hash timing",
    )
    sat_solve = commands.add_parser("sat-solve", help="solve a DIMACS file with an in-process native backend")
    sat_solve.add_argument("--input", required=True, help="DIMACS CNF input file")
    sat_solve.add_argument(
        "--backend", choices=("auto", "pysat", "cryptosat", "pycosat"), default="auto"
    )
    sat_solve.add_argument("--solver-name", default="cadical195", help="PySAT solver name")
    commands.add_parser("selftest", help="run reference, arithmetic, WIF, and length-extension checks")
    solver_selftest = commands.add_parser(
        "sat-selftest",
        help="smoke-test discovered SAT solvers with small SAT and UNSAT formulas",
    )
    solver_selftest.add_argument("--timeout", type=float, default=10.0, help="per-formula timeout in seconds")
    mq_cnf = commands.add_parser(
        "mq-cnf",
        help="encode quadratic Boolean ANF equations as ordinary DIMACS CNF",
        description=(
            "Read JSON equations over GF(2), share quadratic-product Tseitin variables, "
            "and emit ordinary DIMACS CNF compatible with all discovered solvers."
        ),
    )
    mq_cnf.add_argument(
        "--equations",
        required=True,
        help=(
            "JSON file with num_variables and equations; each equation has "
            "quadratic_terms, linear_terms, and rhs"
        ),
    )
    mq_cnf.add_argument("--output", default="-", help="DIMACS path, or - for stdout")

    number = commands.add_parser("number-theory", help="run small number-theory checks")
    operations = number.add_subparsers(dest="operation", required=True)
    gcd_parser = operations.add_parser("gcd", help="extended Euclidean algorithm")
    gcd_parser.add_argument("a", type=int)
    gcd_parser.add_argument("b", type=int)
    phi_parser = operations.add_parser("totient", help="Euler's totient function")
    phi_parser.add_argument("n", type=int)
    for operation in ("fermat", "euler"):
        check_parser = operations.add_parser(operation, help=f"{operation.title()} congruence check")
        check_parser.add_argument("a", type=int)
        check_parser.add_argument("n", type=int)
    rsa_roundtrip = commands.add_parser(
        "rsa-roundtrip",
        help="demonstrate raw RSA modular exponentiation with a toy key",
        description=(
            "Compute c = m**e mod n and m' = c**d mod n, then report whether m' == m. "
            "Raw RSA is unpadded and must not be used to protect real messages."
        ),
    )
    rsa_roundtrip.add_argument("--modulus", type=int, required=True, help="RSA modulus n")
    rsa_roundtrip.add_argument("--public-exponent", type=int, required=True, help="public exponent e")
    rsa_roundtrip.add_argument("--private-exponent", type=int, required=True, help="private exponent d")
    rsa_roundtrip.add_argument("--message", type=int, required=True, help="integer m in [0, n)")
    rsa_broadcast = commands.add_parser(
        "rsa-hastad-broadcast",
        help="recover a repeated unpadded toy RSA message from broadcast ciphertexts",
    )
    rsa_broadcast.add_argument(
        "--ciphertext",
        type=int,
        action="append",
        required=True,
        help="ciphertext integer; repeat once per recipient",
    )
    rsa_broadcast.add_argument(
        "--modulus",
        type=int,
        action="append",
        required=True,
        help="recipient modulus; repeat in the same order as --ciphertext",
    )
    rsa_broadcast.add_argument(
        "--public-exponent",
        type=int,
        required=True,
        help="shared public exponent",
    )
    rsa_gcd = commands.add_parser(
        "rsa-batch-gcd",
        help="find pairwise shared divisors across RSA moduli",
    )
    rsa_gcd.add_argument(
        "--modulus",
        type=int,
        action="append",
        required=True,
        help="RSA modulus to compare; repeat for each modulus",
    )
    rsa_rho = commands.add_parser(
        "rsa-pollard-rho",
        help="run a bounded Pollard–Brent factor search on a toy RSA modulus",
    )
    rsa_rho.add_argument("--modulus", type=int, required=True)
    rsa_rho.add_argument("--max-iterations", type=int, default=1_000_000)
    rsa_rho.add_argument("--batch-size", type=int, default=128)
    rsa_rho.add_argument("--max-attempts", type=int, default=16)
    rsa_rho.add_argument("--seed", type=int, help="optional nonnegative seed for reproducible runs")
    majority = commands.add_parser(
        "sha256-maj-invert",
        help="invert one unknown word in a 32-bit SHA majority operation",
    )
    majority.add_argument("--output", type=_word32, required=True, help="known MAJ output word")
    majority.add_argument("--a", type=_word32, help="known input word a")
    majority.add_argument("--b", type=_word32, help="known input word b")
    majority.add_argument("--c", type=_word32, help="known input word c")
    choice = commands.add_parser(
        "sha256-ch-invert",
        help="analyze unknown input bits in a 32-bit SHA choice operation",
    )
    choice.add_argument("--output", type=_word32, required=True, help="known Ch output word")
    choice.add_argument("--e", type=_word32, help="known selector word e")
    choice.add_argument("--f", type=_word32, help="known true-branch word f")
    choice.add_argument("--g", type=_word32, help="known false-branch word g")

    for name in ("recovery", "research"):
        commands.add_parser(name, help=f"{name} workflow (not yet implemented)")
    sha_cnf = commands.add_parser(
        "sha256-cnf",
        help="generate or solve a bounded SHA-256 CNF research model",
        description=(
            "Generate DIMACS for a reduced/full-round SHA-256 compression or fixed-length "
            "hash-preimage experiment. Full-round preimage solving is not practically feasible."
        ),
    )
    sha_cnf.add_argument("--mode", choices=("compression", "hash"), default="hash")
    sha_cnf.add_argument("--target", type=_hex_bytes, required=True, help="32-byte target state/digest in hex")
    sha_cnf.add_argument("--rounds", type=int, default=64, help="round count from 1 to 64")
    sha_cnf.add_argument(
        "--message-length",
        type=int,
        help="exact hash input length in bytes; longer messages create multi-block CNF models",
    )
    sha_cnf.add_argument(
        "--initial-state",
        type=_hex_bytes,
        default=b"".join(
            value.to_bytes(4, "big")
            for value in (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                          0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
        ),
        help="compression chaining state as 32-byte hex",
    )
    sha_cnf.add_argument(
        "--fix-bit",
        action="append",
        type=_fixed_bit,
        default=[],
        metavar="INDEX=0|1",
        help="fix an input bit (input byte order, most-significant bit first); repeatable",
    )
    sha_cnf.add_argument("--output", default="-", help="DIMACS path, or - for stdout")
    sha_cnf.add_argument(
        "--diagnostics-output",
        help="write structural CNF metrics as JSON; propagation strength is not inferred",
    )
    sha_cnf.add_argument("--solver", help="optional external SAT solver executable")
    sha_cnf.add_argument("--timeout", type=float, default=60.0, help="solver timeout in seconds")
    sha_cnf.add_argument(
        "--cube-depth",
        type=int,
        default=0,
        help="partition the first N unfixed input bits into 2**N solver cubes",
    )
    sha_cnf.add_argument(
        "--parallel-workers",
        type=int,
        default=4,
        help="maximum independent solver processes for cube mode",
    )
    sha_cnf.add_argument(
        "--track-dag",
        action="store_true",
        help="track the SHA Boolean circuit as a validated equation DAG",
    )
    sha_cnf.add_argument(
        "--dag-output",
        help="write tracked Boolean circuit structure as JSON (enables --track-dag)",
    )
    sha_cnf.add_argument(
        "--xor3-encoding",
        choices=("direct", "chain"),
        default="direct",
        help="three-input XOR encoding: direct eight-clause gate or two XOR2 gates",
    )
    agent_solve = commands.add_parser(
        "sha256-agent-solve",
        help="use optional LLM heuristics to choose a bounded SHA-256 SAT cube partition",
        description=(
            "LLM agents suggest input-bit split order only. The target digest and candidate stay local; "
            "the SAT solver checks every cube and Keylab verifies any candidate."
        ),
    )
    agent_solve.add_argument("--target", type=_hex_bytes, required=True, help="32-byte target digest in hex")
    agent_solve.add_argument("--message-length", type=int, required=True, help="exact message length in bytes")
    agent_solve.add_argument("--rounds", type=int, default=15, help="round count from 1 to 64")
    agent_solve.add_argument("--solver", required=True, help="external SAT solver executable")
    agent_solve.add_argument("--agent-model", default="gpt-4.1-mini", help="OpenAI API model for planner roles")
    agent_solve.add_argument("--cube-depth", type=int, default=4, help="split into 2**depth complete cubes (1..16)")
    agent_solve.add_argument("--parallel-workers", type=int, default=4, help="maximum solver worker processes")
    agent_solve.add_argument("--timeout", type=float, default=60.0, help="timeout per SAT cube in seconds")
    agent_solve.add_argument(
        "--fix-bit", action="append", type=_fixed_bit, default=[], metavar="INDEX=0|1",
        help="fix an input bit locally; repeatable",
    )
    ripemd_cnf = commands.add_parser(
        "ripemd160-cnf",
        help="generate or solve a fixed-length reduced/full-step RIPEMD-160 preimage model",
        description=(
            "Generate DIMACS for a one-block (0..55 byte) RIPEMD-160 preimage model. "
            "Full 80-step preimage solving is not practically feasible."
        ),
    )
    ripemd_cnf.add_argument("--target", type=_hex_bytes, required=True, help="20-byte target digest in hex")
    ripemd_cnf.add_argument("--message-length", type=int, required=True, help="exact input length, 0..55 bytes")
    ripemd_cnf.add_argument("--steps", type=int, default=80, help="steps per parallel branch, 1..80")
    ripemd_cnf.add_argument(
        "--fix-bit",
        action="append",
        type=_fixed_bit,
        default=[],
        metavar="INDEX=0|1",
        help="fix an input bit (byte order, most-significant bit first); repeatable",
    )
    ripemd_cnf.add_argument("--output", default="-", help="DIMACS path, or - for stdout")
    ripemd_cnf.add_argument(
        "--diagnostics-output",
        help="write structural CNF metrics as JSON; propagation strength is not inferred",
    )
    ripemd_cnf.add_argument("--solver", help="optional external SAT solver executable")
    ripemd_cnf.add_argument("--timeout", type=float, default=60.0, help="solver timeout in seconds")
    prefix_cnf = commands.add_parser(
        "sha256-prefix-cnf",
        help="generate or solve an educational secret-prefix SHA-256 model",
        description=(
            "Model SHA256(secret || known_message) at a fixed secret length. "
            "Secret-prefix SHA-256 is not a secure MAC; use HMAC-SHA-256."
        ),
    )
    prefix_cnf.add_argument("--target", type=_hex_bytes, required=True, help="32-byte target digest in hex")
    prefix_cnf.add_argument("--message", type=_hex_bytes, required=True, help="known message bytes in hex")
    prefix_cnf.add_argument("--secret-length", type=int, required=True, help="secret length in bytes")
    prefix_cnf.add_argument("--rounds", type=int, default=64, help="round count from 1 to 64")
    prefix_cnf.add_argument("--output", default="-", help="DIMACS path, or - for stdout")
    prefix_cnf.add_argument("--solver", help="optional external SAT solver executable")
    prefix_cnf.add_argument("--timeout", type=float, default=60.0, help="solver timeout in seconds")
    prefix_cnf.add_argument(
        "--track-dag",
        action="store_true",
        help="track the SHA Boolean circuit as a validated equation DAG",
    )
    prefix_cnf.add_argument(
        "--dag-output",
        help="write tracked Boolean circuit structure as JSON (enables --track-dag)",
    )
    sha_benchmark = commands.add_parser(
        "sha256-cnf-benchmark",
        help="measure SHA-256 CNF generation and optional solving with a fixed known input",
        description=(
            "Benchmarks CNF construction and known-input solver verification, not unconstrained "
            "preimage search. Defaults to rounds 14 through 16; round 17 is the first round "
            "that requires message-schedule expansion."
        ),
    )
    sha_benchmark.add_argument("--start-round", type=int, default=14)
    sha_benchmark.add_argument("--end-round", type=int, default=16)
    sha_benchmark.add_argument(
        "--solver",
        action="append",
        help=(
            "solver executable; repeat to compare solvers on the same generated models. "
            "Defaults to the first supported solver found on PATH"
        ),
    )
    sha_benchmark.add_argument("--timeout", type=float, default=30.0, help="per-round solver timeout")
    sha_benchmark.add_argument(
        "--xor3-encoding",
        choices=("direct", "chain", "both"),
        default="both",
        help="compare direct and chained XOR3 encodings, or run only one",
    )
    sha_benchmark.add_argument(
        "--csv-output",
        help="optional CSV path for comparing formula size and per-solver timings",
    )
    throughput_benchmark = commands.add_parser(
        "sat-throughput-benchmark",
        help="measure reduced-hash cube-solving throughput across worker counts",
        description=(
            "Compare solver wall time, completed cubes per second, and speedup against one "
            "worker. Cubes assign selected input bits; they do not directly fix internal "
            "message-schedule words."
        ),
    )
    throughput_benchmark.add_argument(
        "--hash",
        dest="hash_name",
        choices=("sha256", "ripemd160"),
        default="sha256",
    )
    throughput_benchmark.add_argument("--rounds", type=int, default=15)
    throughput_benchmark.add_argument("--cube-depth", type=int, default=4)
    throughput_benchmark.add_argument(
        "--workers",
        type=int,
        nargs="+",
        default=[1, 2, 4, 8],
    )
    throughput_benchmark.add_argument("--timeout-per-cube", type=float, default=30.0)
    throughput_benchmark.add_argument(
        "--solver",
        help="SAT solver executable (defaults to the first supported solver on PATH)",
    )
    throughput_benchmark.add_argument(
        "--csv-output",
        help="optional CSV path for measured worker timings and throughput",
    )
    hash_cnf_test = commands.add_parser(
        "hash-cnf-selftest",
        help="verify known inputs against reduced-round SHA-256 or RIPEMD-160 CNF models",
        description=(
            "Build fixed-input CNF models for selected reduced-round counts and, when a solver "
            "is available, verify each model returns the known message. This checks model wiring, "
            "not unconstrained preimage-solving capability."
        ),
    )
    hash_cnf_test.add_argument("--hash", dest="hash_name", choices=("sha256", "ripemd160"), required=True)
    hash_cnf_test.add_argument(
        "--rounds",
        type=int,
        nargs="+",
        required=True,
        help="one or more reduced round/step counts (SHA-256: 1..64; RIPEMD-160: 1..80)",
    )
    hash_cnf_test.add_argument(
        "--message",
        type=_hex_bytes,
        default=b"keylab-stage3".hex(),
        help="known test message encoded as hex; RIPEMD-160 tests require at most 55 bytes",
    )
    hash_cnf_test.add_argument(
        "--solver",
        help="solver executable; defaults to the first supported solver found on PATH",
    )
    hash_cnf_test.add_argument("--timeout", type=float, default=60.0, help="per-model solver timeout")
    extension = commands.add_parser(
        "sha256-length-extension",
        help="demonstrate length extension against an insecure SHA256(secret || message) tag",
        description=(
            "Educational demonstration only. Do not use secret-prefix SHA-256 as a MAC; "
            "use HMAC-SHA-256."
        ),
    )
    extension.add_argument("--tag", type=_hex_bytes, required=True, help="observed SHA-256 tag in hex")
    extension.add_argument("--message", type=_hex_bytes, required=True, help="known message bytes in hex")
    extension.add_argument("--secret-length", type=int, required=True, help="guessed secret length in bytes")
    extension.add_argument("--suffix", type=_hex_bytes, required=True, help="attacker-appended bytes in hex")
    address_hash = commands.add_parser(
        "address-hash",
        help="decode P2PKH/P2SH/P2WPKH/P2TR address payload data",
    )
    address_hash.add_argument("address", help="mainnet or testnet P2PKH/P2SH/P2WPKH/P2TR address")
    wif_derive = commands.add_parser(
        "wif-derive",
        help="derive addresses from a WIF, prompting with hidden input by default",
    )
    wif_derive.add_argument("--wif", help="WIF input (visible in shell history/process context; prefer hidden prompt)")
    wif_derive.add_argument(
        "--show-private", action="store_true", help="include private scalar hex in output explicitly"
    )
    wif_derive.add_argument(
        "--show-wif", action="store_true", help="echo the input WIF in output explicitly"
    )
    symbolic_roundtrip = commands.add_parser(
        "sha256-symbolic-roundtrip",
        help="solve a free-input reduced-round SHA-256 model and verify its candidate",
        description="A wiring check, not a full SHA-256 preimage-recovery claim. Keep the message short and round count modest.",
    )
    symbolic_roundtrip.add_argument("--message", type=_hex_bytes, default=b"A", help="fixture message in hex (default: 41)")
    symbolic_roundtrip.add_argument("--rounds", type=int, default=2)
    symbolic_roundtrip.add_argument("--backend", choices=("auto", "pysat", "cryptosat", "pycosat"), default="auto")
    symbolic_roundtrip.add_argument("--solver-name", default="cadical195")
    symbolic_roundtrip.add_argument("--xor3-encoding", choices=("direct", "chain"), default="direct")
    sha_stream = commands.add_parser(
        "sha256-stream",
        help="hash a binary file or stdin as a byte stream",
        description=(
            "Hash input incrementally with standard SHA-256 at 64 rounds, or the project's "
            "experimental reduced-round SHA-256 for 1 to 63 rounds."
        ),
    )
    sha_stream.add_argument("--input", default="-", help="binary input file path, or - for stdin")
    sha_stream.add_argument("--rounds", type=int, default=64, help="round count from 1 to 64")
    reverse_compress = commands.add_parser(
        "sha256-reverse-compress",
        help="reverse every SHA-256 compression round when the exact block is known",
        description=(
            "Check an exact 64-byte block against a compression output state, then emit all recovered "
            "working states. This validates known-block round inversion; it does not recover unknown blocks."
        ),
    )
    reverse_compress.add_argument("--output-state", type=_hex_bytes, required=True, help="32-byte feed-forward output state")
    reverse_compress.add_argument("--block", type=_hex_bytes, required=True, help="exact 64-byte compression block")
    reverse_compress.add_argument("--rounds", type=int, default=64, help="compression rounds from 1 to 64")
    reverse_compress.add_argument(
        "--initial-state",
        type=_hex_bytes,
        default=b"".join(
            word.to_bytes(4, "big")
            for word in (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                         0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
        ),
        help="32-byte starting chaining state; defaults to the SHA-256 IV",
    )
    backward_ledger = commands.add_parser(
        "sha256-backward-ledger",
        help="trace the numeric SHA-256 state window before its unresolved E-state boundary",
        description=(
            "Remove feed-forward and recover up to four A-state words from a one-block "
            "SHA-256-shaped digest. This is a numerical trace, not preimage inversion."
        ),
    )
    backward_ledger.add_argument("--target", type=_hex_bytes, required=True, help="32-byte digest in hex")
    backward_ledger.add_argument(
        "--message-length",
        type=int,
        required=True,
        help="one-block message length in bytes, 0..55",
    )
    backward_ledger.add_argument(
        "--rounds",
        type=int,
        default=64,
        help="round count used to generate the digest, from 8 to 64",
    )
    backward_ledger.add_argument(
        "--output",
        default="-",
        help="JSON ledger path, or - to write the report to stdout",
    )
    backward_ledger.add_argument(
        "--known-message",
        type=_hex_bytes,
        help=(
            "optional known message bytes in hex; evaluates the schedule and checks "
            "whether the message matches the supplied target"
        ),
    )
    backward_ledger.add_argument(
        "--block",
        type=_hex_bytes,
        help="exact 64-byte padded compression block; enables complete reverse trace",
    )
    backward_ledger.add_argument(
        "--reverse-to-round",
        type=int,
        help="report the exact working state after this many rounds (for example 32); requires --block",
    )
    forward_feed = commands.add_parser(
        "sha256-forward-feed",
        help="prepend an exact 512-bit block and verify SHA-256 forward feed-forward",
        description=(
            "Treat --prefix-block as the first complete SHA-256 block, append --suffix, "
            "pad with the full message length, and cross-check the resulting digest with hashlib."
        ),
    )
    forward_feed.add_argument("--prefix-block", type=_hex_bytes, required=True, help="exact 64-byte (512-bit) prefix block")
    forward_feed.add_argument("--suffix", type=_hex_bytes, default=b"", help="bytes appended after the prefix block, in hex")
    forward_feed.add_argument("--target", type=_hex_bytes, help="optional expected 32-byte SHA-256 digest")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI without doing network activity or unconstrained key searches."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "backends":
        return _backend_status()
    if args.command in {"audit", "feature-audit"}:
        return _feature_audit()
    if args.command == "benchmark-pubkey":
        if args.iterations < 1 or args.warmup < 0:
            parser.error("--iterations must be positive and --warmup nonnegative")
        return _benchmark_pubkey(args, parser)
    if args.command == "benchmark-ec":
        if args.count < 1 or args.seed < 0 or args.repetitions < 1:
            parser.error("--count and --repetitions must be positive; --seed must be nonnegative")
        return _benchmark_ec(args, parser)
    if args.command == "benchmark-wifs":
        if args.count < 1 or args.warmup < 0 or args.repetitions < 1:
            parser.error("--count and --repetitions must be positive; --warmup nonnegative")
        return _benchmark_wifs(args, parser)
    if args.command == "benchmark-hash160":
        if args.count < 1:
            parser.error("--count must be positive")
        return _benchmark_hash160(args, parser)
    if args.command == "sat-solve":
        return _sat_solve(args, parser)
    if args.command == "selftest":
        return _selftest()
    if args.command == "sat-selftest":
        if args.timeout <= 0:
            parser.error("--timeout must be positive")
        return _sat_selftest(args)
    if args.command == "mq-cnf":
        return _mq_cnf(args, parser)
    if args.command == "number-theory":
        return _number_theory(args)
    if args.command == "rsa-roundtrip":
        return _rsa_exponentiation(args, parser)
    if args.command == "rsa-hastad-broadcast":
        return _rsa_hastad_broadcast(args, parser)
    if args.command == "rsa-batch-gcd":
        return _rsa_batch_gcd(args, parser)
    if args.command == "rsa-pollard-rho":
        return _rsa_pollard_rho(args, parser)
    if args.command == "sha256-maj-invert":
        return _sha256_majority_invert(args, parser)
    if args.command == "sha256-ch-invert":
        return _sha256_choice_invert(args, parser)
    if args.command == "sha256-cnf":
        return _sha256_cnf(args, parser)
    if args.command == "sha256-agent-solve":
        return _sha256_agent_solve(args, parser)
    if args.command == "ripemd160-cnf":
        return _ripemd160_cnf(args, parser)
    if args.command == "sha256-prefix-cnf":
        return _sha256_secret_prefix_cnf(args, parser)
    if args.command == "sha256-cnf-benchmark":
        return _sha256_cnf_benchmark(args, parser)
    if args.command == "sat-throughput-benchmark":
        return _sat_throughput_benchmark(args, parser)
    if args.command == "hash-cnf-selftest":
        if args.timeout <= 0:
            parser.error("--timeout must be positive")
        return _hash_cnf_selftest(args, parser)
    if args.command == "sha256-length-extension":
        return _sha256_length_extension(args, parser)
    if args.command == "address-hash":
        return _address_hash(args, parser)
    if args.command == "wif-derive":
        return _wif_derive(args, parser)
    if args.command == "sha256-symbolic-roundtrip":
        return _sha256_symbolic_roundtrip(args, parser)
    if args.command == "sha256-stream":
        return _sha256_stream(args, parser)
    if args.command == "sha256-reverse-compress":
        return _sha256_reverse_compress_cli(args, parser)
    if args.command == "sha256-forward-feed":
        if args.target is not None and len(args.target) != 32:
            parser.error("--target must be exactly 32 bytes")
        return _sha256_forward_feed_cli(args, parser)
    if args.command == "sha256-backward-ledger":
        return _sha256_backward_ledger(args, parser)
    print(f"{args.command}: not yet implemented", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
