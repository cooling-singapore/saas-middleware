
const initialData = {
    dialogOpen: false,
    seconds: 0,
    processorCount: 10,
    processorTypes: {
        'Processor A': {
            name: 'Processor A', type: 'AIA Processor', versions: [{ id: 'v1.0', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v2.0', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v3.0', description: 'initial verison', url: 'https://github.com/' }]
        },
        'Processor B': {
            name: 'Processor B', type: 'EnviMat Processor', versions: [{ id: 'v1.0', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v1.1', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v2.1', description: 'initial verison', url: 'https://github.com/' }]
        },
        'Processor C': {
            name: 'Processor C', type: 'Ansys Fluent Processor', versions: [{ id: 'v1.0', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v1.1', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v2.1', description: 'initial verison', url: 'https://github.com/' }]
        },
        'Processor D': {
            name: 'Processor D', type: 'IEM Processor', versions: [{ id: 'v1.0', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v1.1', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v2.1', description: 'initial verison', url: 'https://github.com/' }]
        },
        'Processor E': {
            name: 'Processor E', type: 'SingV Processor', versions: [{ id: 'v1.0', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v1.1', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v2.1', description: 'initial verison', url: 'https://github.com/' }]
        },
        'Processor F': {
            name: 'Processor F', type: 'WRF Processor', versions: [{ id: 'v1.0', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v1.1', description: 'initial verison', url: 'https://github.com/' },
            { id: 'v2.1', description: 'initial verison', url: 'https://github.com/' }]
        },

    },
    processorTypeOrder: ['Processor A', 'Processor B', 'Processor C', 'Processor D', 'Processor E', 'Processor F'],
    processors: {
        'processor-1': {
            id: 'processor-1', name: 'Processor 1', type: 'AIA Processor', status: 1, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Data Processing', status: 'Processing' },
            { id: '3', description: 'Result Calculating', status: 'Queued' }]
        },
        'processor-2': {
            id: 'processor-2', name: 'Processor 2', type: 'EnviMat Processor', status: 2, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing' }]
        },
        'processor-3': {
            id: 'processor-3', name: 'Processor 3', type: 'EnviMat Processor', status: 3, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing' }]
        },
        'processor-4': {
            id: 'processor-4', name: 'Processor 4', type: 'SingV Processor', status: 2, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing', status: 'Queued' }]
        },
        'processor-5': {
            id: 'processor-5', name: 'Processor 5', type: 'WRF Processor', status: 2, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing', status: 'Queued' }]
        },
        'processor-6': {
            id: 'processor-6', name: 'Processor 6', type: 'Ansys Fluent Processor', status: 3, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing', status: 'Queued' }]
        },
        'processor-7': {
            id: 'processor-7', name: 'Processor 7', type: 'AIA Processor', status: 1, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing', status: 'Queued' }]
        },
        'processor-8': {
            id: 'processor-8', name: 'Processor 8', type: 'Ansys Fluent Processor', status: 1, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing', status: 'Queued' }]
        },
        'processor-9': {
            id: 'processor-9', name: 'Processor 9', type: 'SingV Processor', status: 2, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing', status: 'Queued' }]
        },
        'processor-10': {
            id: 'processor-10', name: 'Processor 10', type: 'Ansys Fluent Processor', status: 1, jobs: [{ id: '1', description: 'Data Loading', status: 'Finished' },
            { id: '2', description: 'Simuating', status: 'Processing' },
            { id: '3', description: 'Result Processing', status: 'Queued' }]
        },
    },
    dataObjects: {
        'dataObejct-1': { id: 'dataObejct-1', name: 'Data Obejct 1', type: '3D Model' },
        'dataObejct-2': { id: 'dataObejct-2', name: 'Data Obejct 2', type: 'Color Map' },
        'dataObejct-3': { id: 'dataObejct-3', name: 'Data Obejct 3', type: 'Binary File' },
        'dataObejct-4': { id: 'dataObejct-4', name: 'Data Obejct 4', type: 'Color Map' },
        'dataObejct-5': { id: 'dataObejct-5', name: 'Data Obejct 5', type: 'Color Map' },
        'dataObejct-6': { id: 'dataObejct-6', name: 'Data Obejct 6', type: 'Color Map' },
        'dataObejct-7': { id: 'dataObejct-7', name: 'Data Obejct 7', type: 'Binary File' },
        'dataObejct-8': { id: 'dataObejct-8', name: 'Data Obejct 8', type: 'CSV File' },
    },
    nodes: {
        'node-1': {
            id: 'node-1',
            title: 'Node 1',
            processorIds: ['processor-1', 'processor-2', 'processor-3'],
            dataObjectIds: ['dataObejct-1', 'dataObejct-2'],
        },
        'node-2': {
            id: 'node-2',
            title: 'Node 2',
            processorIds: ['processor-4'],
            dataObjectIds: ['dataObejct-3', 'dataObejct-4'],
        },
        'node-3': {
            id: 'node-3',
            title: 'Node 3',
            processorIds: ['processor-5', 'processor-6', 'processor-7'],
            dataObjectIds: ['dataObejct-5', 'dataObejct-6'],
        },
        'node-4': {
            id: 'node-4',
            title: 'Node 4',
            processorIds: ['processor-8', 'processor-9'],
            dataObjectIds: ['dataObejct-7'],
        },
        'node-5': {
            id: 'node-5',
            title: 'Node 5',
            processorIds: ['processor-10'],
            dataObjectIds: ['dataObejct-8'],
        },
    },
    nodeOrder: ['node-1', 'node-2', 'node-3', 'node-4', 'node-5'],
};

export default initialData;