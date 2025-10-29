// scrolling.test.js
const fs = require('fs');
const path = require('path');
// --- Load the Function ---
// 1. Read the file content as a string.
const functionBody = fs.readFileSync(
  path.resolve(__dirname, 'scrolling.js'),
  'utf8',
);

// 2. Evaluate the string to get the async function.
// We wrap it in a function constructor.
const scrollingFunction = new Function(`return ${functionBody};`)();

// --- Test Suite ---
describe('scrollingFunction', () => {
  let targetElement;
  let mockMathRandom;

  // --- Setup & Teardown ---
  beforeEach(() => {
    // 1. Use Fake Timers
    // This allows us to control setTimeout, requestAnimationFrame, etc.
    jest.useFakeTimers();

    // 2. Mock Math.random()
    // We mock this to get predictable results for scrolling calculations.
    mockMathRandom = jest.spyOn(Math, 'random').mockReturnValue(0.5);

    // 3. Set up DOM
    document.body.innerHTML = `
      <div>Some header text to add content density</div>
      <p>${'hello '.repeat(500)}</p> 
      <div id="target-element" style="width: 100px; height: 100px;">
        Target
      </div>
      <div style="height: 3000px;"></div>
    `;
    targetElement = document.getElementById('target-element');

    // 4. Mock Viewport
    Object.defineProperty(window, 'innerHeight', {
      writable: true,
      value: 800,
    });
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      value: 600,
    });
    
    // 5. Mock Core Scrolling Properties on document.documentElement
    // (This is what getScrollableParent will find for the main window)
    Object.defineProperties(document.documentElement, {
      scrollTop: { value: 0, writable: true },
      scrollLeft: { value: 0, writable: true },
      scrollHeight: { value: 4000, writable: true },
      scrollWidth: { value: 600, writable: true },
      clientHeight: { value: 800, writable: true },
      clientWidth: { value: 600, writable: true },
    });

    // 6. Mock Core Methods
    // a. scrollBy
    document.documentElement.scrollBy = jest.fn();
    
    // b. getBoundingClientRect (Default: element is far down the page)
    jest.spyOn(targetElement, 'getBoundingClientRect').mockReturnValue({
      top: 2000,
      bottom: 2100,
      left: 10,
      right: 110,
      width: 100,
      height: 100,
    });

    // c. getComputedStyle (To ensure getScrollableParent finds doc.element)
    jest.spyOn(window, 'getComputedStyle').mockImplementation((el) => {
      if (el === document.documentElement) {
        return { overflowY: 'scroll', overflowX: 'auto', display: 'block' };
      }
      if (el === targetElement) {
        return { display: 'block' }; // For density check
      }
      return { display: 'block', overflow: 'visible' };
    });

    // d. elementFromPoint (For wheel events)
    document.elementFromPoint = jest
      .fn()
      .mockReturnValue(document.body);

    // e. dispatchEvent (To spy on wheel events)
    document.body.dispatchEvent = jest.fn();
  });

  afterEach(() => {
    // Restore all mocks
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  // --- Test Cases ---

  test('should return elementExists: false if selector not found', async () => {
    const result = await scrollingFunction(
      '#not-found',
      0, 0, 0.5, false, 0, 0, false,
    );
    expect(result.elementExists).toBe(false);
    expect(result.isComplete).toBe(true);
  });

  test('should return isIntersecting: true if element is already visible', async () => {
    // Override the mock to place the element in view
    jest.spyOn(targetElement, 'getBoundingClientRect').mockReturnValue({
      top: 100,
      bottom: 200,
      left: 100,
      right: 200,
    });

    const result = await scrollingFunction(
      '#target-element',
      0, 0, 0.5, false, 0, 0, false,
    );
    expect(result.isIntersecting).toBe(true);
    expect(result.isComplete).toBe(true);
  });

  test('should calculate vertical scroll with scrollBy (trackpad)', async () => {
    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, false, 0, 0, false, // readDensityFactor = 0
    );

    // Advance timers for stabilization
    jest.advanceTimersByTime(2000);
    const result = await scrollPromise;

    // --- Calculations (for validation) ---
    // targetViewportPosition = 800 * (0.2 + 0.5 * 0.6) = 800 * 0.5 = 400
    // targetScrollTop = 2000 (element.top) - 400 = 1600
    // distanceToTargetY = 1600 (target) - 0 (start) = 1600
    // contentDensity = ~1.0 (from 500 'hello 's)
    // densityImpact = 1.0 (since readDensityFactor = 0)
    // randomFactor = 0.6 + 0.5 * 0.4 = 0.8
    // chunkFactor = 0.8 * 1.0 = 0.8
    // scrollAmountY = 1600 * 0.8 = 1280

    expect(document.documentElement.scrollBy).toHaveBeenCalledWith({
      top: 1280,
      left: 0,
      behavior: 'smooth', // 1280 > 150
    });
    expect(result.isComplete).toBe(false); // Not complete, as it only scrolled a chunk
    expect(result.verticalDelta).toBeCloseTo(1600);
    expect(result.contentDensity).toBeCloseTo(1.016); // (500*6 + 5) / 3000
  });

  test('should use injectedDeltaY when provided', async () => {
    const scrollPromise = scrollingFunction(
      '#target-element',
      500, 0, 0.5, false, 0, 0, false, // Injected 500Y
    );
    jest.advanceTimersByTime(2000);
    await scrollPromise;

    expect(document.documentElement.scrollBy).toHaveBeenCalledWith({
      top: 500,
      left: 0,
      behavior: 'smooth',
    });
  });

  test('should use mouse wheel simulation', async () => {
    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, true, 300, 400, false, // useMouseWheel: true, coords 300,400
    );
    jest.advanceTimersByTime(2000);
    const result = await scrollPromise;

    // Same scroll amount as the 'scrollBy' test
    const expectedDeltaY = 1280;

    expect(document.documentElement.scrollBy).not.toHaveBeenCalled();
    expect(document.elementFromPoint).toHaveBeenCalledWith(300, 400);
    expect(document.body.dispatchEvent).toHaveBeenCalledTimes(1);

    const dispatchedEvent = document.body.dispatchEvent.mock.calls[0][0];
    expect(dispatchedEvent.type).toBe('wheel');
    expect(dispatchedEvent.deltaY).toBeCloseTo(expectedDeltaY);
    expect(dispatchedEvent.clientX).toBe(300);
    expect(dispatchedEvent.clientY).toBe(400);

    expect(result.isComplete).toBe(false);
  });

  test('should use detent mouse wheel simulation', async () => {
    // Need to run timers as the function loops
    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, true, 300, 400, true, // isDetentWheel: true
    );

    // Run all pending timers (for the loop)
    jest.runAllTimers();
    const result = await scrollPromise;

    // --- Calculations ---
    // scrollAmountY = 1280 (from 'scrollBy' test)
    // stepSize = 100
    // stepsY = Math.round(1280 / 100) = 13
    
    expect(document.body.dispatchEvent).toHaveBeenCalledTimes(13);

    // Check first and last event
    expect(document.body.dispatchEvent.mock.calls[0][0].deltaY).toBe(100);
    expect(document.body.dispatchEvent.mock.calls[12][0].deltaY).toBe(100);

    expect(result.isComplete).toBe(false);
  });
  
  test('should adjust scroll chunking based on content density', async () => {
    // Set density factor to 1.0 (max impact)
    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 1.0, false, 0, 0, false,
    );
    jest.advanceTimersByTime(2000);
    await scrollPromise;

    // --- Calculations ---
    // distanceToTargetY = 1600
    // contentDensity = ~1.016
    // densityImpact = Math.max(0.1, 1.0 - 1.016 * 1.0) = 0.1
    // randomFactor = 0.8
    // chunkFactor = 0.8 * 0.1 = 0.08
    // scrollAmountY = 1600 * 0.08 = 128
    
    expect(document.documentElement.scrollBy).toHaveBeenCalledWith({
      top: 128,
      left: 0,
      behavior: 'auto', // 128 < 150
    });
  });

  test('should detect completion if scroll boundary is hit', async () => {
    // Mock scrollBy to do nothing (simulating hitting a boundary)
    document.documentElement.scrollBy.mockImplementation(() => {
      // scrollTop remains 0
    });
    
    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, false, 0, 0, false,
    );
    jest.advanceTimersByTime(2000);
    const result = await scrollPromise;

    // scrollAmountY (1280) > 5
    // startScrollTop (0) - endScrollTop (0) < 5
    // -> boundaryHit = true
    expect(result.isComplete).toBe(true);
  });
});