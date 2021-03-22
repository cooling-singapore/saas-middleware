import React from 'react';
import styled from 'styled-components';
import { DragDropContext } from 'react-beautiful-dnd';
import {
    Grid
} from '@material-ui/core';

import initialData from '../data/initialData';
import Node from './node';
import ProcessorTypeList from './processorTypeList';

const Content = styled.div`
    height:100%,
`;

class DomainView extends React.Component {
    state = initialData;

    onDragStart = start => {

    };

    onDragEnd = result => {
        const { destination, source, draggableId, type } = result;
        if (!destination) {
            return;
        }

        if (
            destination.droppableId === source.droppableId &&
            destination.index === source.index
        ) {
            return;
        }

        if (type === 'processor') {
            if (destination.droppableId.includes('processor') && source.droppableId === 'processorType') {
                var id = 'processor-' + (this.state.processorCount + 1);
                this.state.processors[id] = { id: id, name: 'Processor ' + (this.state.processorCount + 1), type: this.state.processorTypes[draggableId].type, status: 1, jobs: [] };

                var destinationId = destination.droppableId.replace('processor', '');
                const finish = this.state.nodes[destinationId];

                const finishProcessorIds = Array.from(finish.processorIds);
                finishProcessorIds.splice(destination.index, 0, id);
                const newFinish = {
                    ...finish,
                    processorIds: finishProcessorIds,
                };

                const newState = {
                    ...this.state,
                    processorCount: (this.state.processorCount + 1),
                    nodes: {
                        ...this.state.nodes,
                        [newFinish.id]: newFinish,
                    },
                }
                this.setState(newState);
                return;
            }
        }

        // TODO: move to a function
        if (type === 'dataObject') {
            var sourceId = source.droppableId.replace('dataObject', '');
            var destinationId = destination.droppableId.replace('dataObject', '');

            const start = this.state.nodes[sourceId];
            const finish = this.state.nodes[destinationId];

            if (start === finish) {
                const newDataObjectIds = Array.from(start.dataObjectIds);
                newDataObjectIds.splice(source.index, 1);
                newDataObjectIds.splice(destination.index, 0, draggableId);

                const newNode = {
                    ...start,
                    dataObjectIds: newDataObjectIds,
                };

                const newState = {
                    ...this.state,
                    nodes: {
                        ...this.state.nodes,
                        [newNode.id]: newNode,
                    },
                };

                this.setState(newState);
                return;
            }

            // Moving from one list to another
            const startDataObjectIds = Array.from(start.dataObjectIds);
            startDataObjectIds.splice(source.index, 1);
            const newStart = {
                ...start,
                dataObjectIds: startDataObjectIds,
            };

            const finishDataObjectIds = Array.from(finish.dataObjectIds);
            finishDataObjectIds.splice(destination.index, 0, draggableId);
            const newFinish = {
                ...finish,
                dataObjectIds: finishDataObjectIds,
            };

            const newState = {
                ...this.state,
                nodes: {
                    ...this.state.nodes,
                    [newStart.id]: newStart,
                    [newFinish.id]: newFinish,
                },
            };

            this.setState(newState);
        }
    }

    // TODO: rework the node data object structure
    onDeleteProcessor = (processorId, nodeId) => {
        const node = this.state.nodes[nodeId];
        const processorIds = Array.from(node.processorIds);
        processorIds.splice(processorId, 1);

        // TODO remove processor from processor list
        // const newProcessors = Array.from(this.state.processors);
        // console.log(newProcessors);
        // newProcessors.splice(processorId, 1);
        // console.log(newProcessors);

        const newNode = {
            ...node,
            processorIds: processorIds,
        }

        const newState = {
            ...this.state,
            // processors
            nodes: {
                ...this.state.nodes,
                [newNode.id]: newNode,
            },
        }

        this.setState(newState);
    };

    // handleClickOpen() {
    //   this.state.dialogOpen = true;
    // };

    // handleClose() {
    //   this.state.dialogOpen = false;
    // };

    tick() {
        this.setState(state => ({
            seconds: state.seconds + 1
        }));
    }

    componentDidMount() {
        // TODO update
        // this.interval = setInterval(() => this.tick(), 1000);
    }

    componentWillUnmount() {
        clearInterval(this.interval);
    }

    render() {
        return (
            <Content>
                {/* <div>
                        Update: {this.state.seconds}
                    </div> 
                */}
                <DragDropContext onDragEnd={this.onDragEnd}>
                    <Grid
                        container
                        spacing={2}
                        direction='row'
                        justify='center'
                        alignItems='stretch'
                        wrap='nowrap'
                        style={{ padding: '10px' }}
                    >
                        <Grid item style={{ backgroundColor: '#F4F4F4' }}>
                            <ProcessorTypeList processorTypes={this.state.processorTypes} processorTypeOrder={this.state.processorTypeOrder} />
                        </Grid>
                    
                        {this.state.nodeOrder.map(nodeId => {
                            const node = this.state.nodes[nodeId];
                            const processors = node.processorIds.map(processorId => this.state.processors[processorId]);
                            const dataObjects = node.dataObjectIds.map(dataObjectId => this.state.dataObjects[dataObjectId]);

                            return <Node key={node.id} node={node} processors={processors} dataObjects={dataObjects} onDeleteProcessor={this.onDeleteProcessor} handleClickOpen={this.handleClickOpen} handleClose={this.handleClose} />;
                        })}

                    </Grid>
                </DragDropContext>
            </Content>
        );
    }
}

export default DomainView;