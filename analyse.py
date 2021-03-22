#!/usr/bin/env python3
import angr
import claripy
import json
import sys
from itertools import islice

# System V amd64 Aufrufkonventionen
calling_convention = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

# Abbruchbedingung für einzelene Parametertypen:
param_cancelation_conditions = {
    'immediate': lambda reg_state, solver: solver.single_valued(reg_state),
    'string':    lambda reg_state, solver: False,
    'sockaddr':  lambda reg_state, solver: False,
    'socklen':  lambda reg_state, solver: False,
}

# Definition von Funktionen, die je nach Parametertyp
# die erlaubte Argumentmenge beschreiben:
param_descriptors = {
    'immediate': lambda *args: resolve_immediate(*args),
    'string':    lambda *args: resolve_string(*args),
    'sockaddr':  lambda *args: resolve_sockaddr(*args),
    'socklen':  lambda *args: resolve_socklen(*args)
}

def main():
    # Binary laden
    binary_path = sys.argv[1] if len(sys.argv) > 1 else './examples/shellroulette'
    p = angr.Project(binary_path,
        auto_load_libs=False,
        use_sim_procedures=True)

    # Eingabe JSON-Dateien einlesen
    input_addrs = load_json(binary_path + '.json')
    model       = load_json('./model.json')

    # Ausgabe JSON
    profile = {}

    # Kontrollflussgraphen rekonstruieren
    p.analyses.CFGFast()

    # Hack, um die rand()-Funktion in shellroulette.c in der Symbex nicht-deterministisch zu machen.
    if binary_path.endswith('shellroulette'):
        def rand_hook(s):
            s.regs.eax = s.solver.BVS('rand_number', 32)
            s.solver.add(s.regs.eax < 2**32)

        p.hook(0x4011f4, rand_hook, length=(0x4011f9-0x4011f4))

    for syscall in input_addrs:
        param_types = model[syscall]

        symbex_state = []
        for addr in input_addrs[syscall]:
            # Jump-sensitive backward symbolic execution durchführen
            def cancelation_condition(symbex_state, it):
                if it >= 2:
                    return True

                for _, param_type, reg_state in iterate_reg_states(param_types, symbex_state):
                    # Die zu dem Parametertypen gehörende Abbruchbedingungen lesen
                    param_cancelation_condition = param_cancelation_conditions[param_type]

                    # Wenn zu einem Parameter noch nicht alle Informationen vorliegen,
                    # dann weitermachen / noch nicht abbrechen.
                    if not param_cancelation_condition(reg_state, symbex_state.solver):
                        return False

                return True

            jbse          = prepare_jbse(cancelation_condition)
            symbex_state += jbse(addr, p)
        
        profile[syscall] = []
        for symbex_substate in symbex_state:
            params_description = []
            for param_idx, param_type, reg_state in iterate_reg_states(param_types, symbex_substate):
                param_descriptor  = param_descriptors[param_type]
                param_description = param_descriptor(reg_state,
                    symbex_substate.memory,
                    symbex_substate.solver)

                params_description.append(param_description)
            profile[syscall].append(params_description)
    
    profile_json = json.dumps(profile)
    print(profile_json)

def iterate_reg_states(param_types, symbex_state):
    param_idx = -1
    for param_type in param_types:
        param_idx += 1

        if param_type == '-':
            continue

        # Parameterregister identifizieren und auslesen
        reg_state = getattr(symbex_state.regs, calling_convention[param_idx])
        yield param_idx, param_type, reg_state

def load_json(path):
    with open(path) as file:
        return json.load(file)

def prepare_jbse(cancelation_condition):
    def jbse(end, p, start = None, it = 0):
        it += 1

        # Einsprungpunkt sichern
        if start is None:
            func  = p.kb.functions.floor_func(end)
            assert(func is not None)
            start = func.addr

        # Symbolic Execution durchführen
        call_state = p.factory.call_state(start)
        sm         = p.factory.simulation_manager(call_state)
        sm.explore(find=end)
        if len(sm.found) != 1:
            raise Exception("Zieladresse nicht erreichbar")

        symbex_state = sm.found[0]
        if cancelation_condition(symbex_state, it):
            return [symbex_state]

        merged_states = []
        for pre in p.kb.callgraph.predecessors(start):
            try:
                merged_states += jbse(end, p, pre, it)
            except:
                return [symbex_state]
        return merged_states

    return jbse

def resolve_immediate(reg_state, memory, solver):
    if not solver.single_valued(reg_state):
        return {}
    
    return {
        'cmp': 'eq',
        'val': solver.eval(reg_state)
    }

def resolve_string(reg_state, memory, solver):
    if not solver.single_valued(reg_state):
        return {
            'cmp': 'prefix',
            'str': ''
        }

    addr = solver.eval(reg_state)

    bs = []
    offset = 0
    while True:
        b = memory.load(addr + offset, 1)
        if not solver.single_valued(b):
            return {
                'cmp': 'prefix',
                'str': ''.join([chr(b) for b in bs])
            }
        b = solver.eval(b)
        if b == 0:
            break
        bs.append(b)
        offset += 1
    return {
        'cmp': 'match',
        'str': ''.join([chr(b) for b in bs])
    }

def resolve_sockaddr(reg_state, memory, solver):
    if not solver.single_valued(reg_state):
        return {
            'family': '*',
            'port': '*',
            'addr': '*'
        }
    
    addr = solver.eval(reg_state)

    fam  = resolve_immediate(memory.load(addr, 2), memory, solver)
    port = resolve_immediate(memory.load(addr+2, 2), memory, solver)

    ip = [None, None, None, None]
    for i in range(4):
        ip[i] = resolve_immediate(memory.load(addr+4+i, 1), memory, solver)

    return {
        'family': fam,
        'port': port,
        'ip': ip
    }

def resolve_socklen(reg_state, memory, solver):
    if not solver.single_valued(reg_state):
        return {}
    
    addr = solver.eval(reg_state)
    return resolve_immediate(memory.load(addr, 4), memory, solver)


main()
