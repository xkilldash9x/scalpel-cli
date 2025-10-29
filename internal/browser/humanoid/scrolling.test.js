// scrolling.test.js

// Import the function directly as a module
const scrollingFunction = require('./scrolling.js');

// --- Test Suite ---
describe('scrollingFunction', () => {
  let targetElement;
  let mockMathRandom;

  // Helper to flush the microtask (promise) queue
  const flushMicrotasks = () => new Promise(jest.requireActual('timers').setImmediate);

  // Helper to simulate wheel scroll effect (Functional Mock for dispatchEvent)
  const simulateWheelScroll = (event) => {
    if (event.type !== 'wheel') {
      return true; // Event dispatched, not cancelled
    }
    const scroller = document.documentElement;
    scroller.scrollTop += event.deltaY || 0;
    scroller.scrollLeft += event.deltaX || 0;
    return true; // Event dispatched, not cancelled
  };

  // --- Setup & Teardown ---
  beforeEach(() => {
    // 1. Use Fake Timers
    jest.useFakeTimers();

    // *** START FIX ***
    // Do NOT polyfill Element.prototype. We will assign mocks to instances.
    // if (typeof Element.prototype.scrollBy !== 'function') {
    //   Element.prototype.scrollBy = jest.fn();
    // }
    // *** END FIX ***

    // 1b. Mock requestAnimationFrame
    jest.spyOn(window, 'requestAnimationFrame').mockImplementation(cb => setTimeout(cb, 16)); // ~60fps

    // 1c. Polyfill WheelEvent
    if (typeof window.WheelEvent === 'undefined') {
      window.WheelEvent = class WheelEvent extends window.MouseEvent {
        constructor(type, init = {}) {
          super(type, init);
          this.deltaX = init.deltaX || 0;
          this.deltaY = init.deltaY || 0;
          this.deltaZ = init.deltaZ || 0;
          this.deltaMode = init.deltaMode || 0;
        }
      };
    }


    // 2. Mock Math.random()
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
    Object.defineProperties(document.documentElement, {
      scrollTop: { value: 0, writable: true, configurable: true },
      scrollLeft: { value: 0, writable: true, configurable: true },
      scrollHeight: { value: 4000, writable: true, configurable: true },
      scrollWidth: { value: 600, writable: true, configurable: true },
      clientHeight: { value: 800, writable: true, configurable: true },
      clientWidth: { value: 600, writable: true, configurable: true },
      isConnected: { value: true, writable: true, configurable: true },
    });

    // 6. Mock Core Methods
    // *** START FIX ***
    // a. scrollBy (Assign a functional mock directly to the instance)
    document.documentElement.scrollBy = jest.fn((options) => {
      if (typeof options === 'object' && options !== null) {
        document.documentElement.scrollTop += options.top || 0;
        document.documentElement.scrollLeft += options.left || 0;
      }
    });
    // *** END FIX ***


    // b. getBoundingClientRect
    jest.spyOn(targetElement, 'getBoundingClientRect').mockReturnValue({
      top: 2000,
      bottom: 2100,
      left: 100,
      right: 200,
      width: 100,
      height: 100,
    });

    // c. getComputedStyle (Main implementation)
    jest.spyOn(window, 'getComputedStyle').mockImplementation((el) => {
      if (el === document.documentElement) {
        return { overflowY: 'scroll', overflowX: 'auto', display: 'block', visibility: 'visible' };
      }
      return { display: 'block', overflow: 'visible', visibility: 'visible' };
    });

    // d. elementFromPoint
    document.elementFromPoint = jest
      .fn()
      .mockReturnValue(document.body);

    // e. dispatchEvent
    const bodyDispatchSpy = jest.spyOn(document.body, 'dispatchEvent').mockImplementation(simulateWheelScroll);
    const docDispatchSpy = jest.spyOn(document.documentElement, 'dispatchEvent').mockImplementation(simulateWheelScroll);
    bodyDispatchSpy.mockClear();
    docDispatchSpy.mockClear();
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
      0, 0, 0, false, 0, 0, false,
    );
    jest.runAllTimers();
    await flushMicrotasks();
    const result = await scrollPromise;

    expect(document.documentElement.scrollBy).toHaveBeenCalledWith({
      top: 1280,
      left: 0,
      behavior: 'smooth',
    });
    expect(result.isComplete).toBe(false);
  });

  test('should calculate horizontal scroll with scrollBy (trackpad)', async () => {
    jest.spyOn(targetElement, 'getBoundingClientRect').mockReturnValue({
      top: 100, bottom: 200, left: 2000, right: 2100,
    });
    document.documentElement.scrollWidth = 3000;

    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, false, 0, 0, false,
    );
    jest.runAllTimers();
    await flushMicrotasks();
    await scrollPromise;

    expect(document.documentElement.scrollBy).toHaveBeenCalledWith({
      top: 0,
      left: 1360,
      behavior: 'smooth',
    });
  });

  test('should use injectedDeltaY when provided', async () => {
    const scrollPromise = scrollingFunction(
      '#target-element',
      500, 0, 0.5, false, 0, 0, false,
    );
    jest.runAllTimers();
    await flushMicrotasks();
    await scrollPromise;

    expect(document.documentElement.scrollBy).toHaveBeenCalledWith(expect.objectContaining({
      top: 500,
      behavior: 'smooth',
    }));
  });

  test('should use behavior: auto for small scroll distances (< 150px) using injectedDelta', async () => {
    const scrollPromise = scrollingFunction(
        '#target-element',
        140, 0, 0, false, 0, 0, false,
    );
    jest.runAllTimers();
    await flushMicrotasks();
    await scrollPromise;

    expect(document.documentElement.scrollBy).toHaveBeenCalledWith(expect.objectContaining({
        top: 140,
        behavior: 'auto',
    }));
  });

  test('should use mouse wheel simulation', async () => {
    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, true, 300, 400, false,
    );
    jest.runAllTimers();
    await flushMicrotasks();
    const result = await scrollPromise;

    const expectedDeltaY = 1280;
    expect(document.documentElement.scrollBy).not.toHaveBeenCalled();
    expect(document.body.dispatchEvent).toHaveBeenCalledTimes(1);
    const dispatchedEvent = document.body.dispatchEvent.mock.calls[0][0];
    expect(dispatchedEvent.deltaY).toBeCloseTo(expectedDeltaY);
    expect(result.isComplete).toBe(false);
  });

  test('should use fallback target for wheel events if cursor is outside viewport', async () => {
    document.elementFromPoint.mockReturnValue(null);
    const fallbackElement = document.createElement('div');
    jest.spyOn(fallbackElement, 'dispatchEvent').mockImplementation(simulateWheelScroll);
    document.body.appendChild(fallbackElement);
    document.elementFromPoint.mockImplementation((x, y) => {
        if (x === 1 && y === 1) return null;
        if (x === 300 && y === 400) return fallbackElement;
        return null;
    });

    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, true, 1, 1, false,
    );
    jest.runAllTimers();
    await flushMicrotasks();
    await scrollPromise;

    expect(fallbackElement.dispatchEvent).toHaveBeenCalled();
  });

  test('should use detent mouse wheel simulation', async () => {
    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, true, 300, 400, true,
    );

    // Manually drive the event loop for the async timer loop
    for (let i = 0; i < 30; i++) {
      jest.runOnlyPendingTimers();
      await flushMicrotasks();
    }
    
    const result = await scrollPromise;
    
    expect(document.body.dispatchEvent).toHaveBeenCalledTimes(13);
    const calls = document.body.dispatchEvent.mock.calls;
    expect(calls[0][0].deltaY).toBe(100);
    expect(calls[12][0].deltaY).toBe(100);
    expect(result.isComplete).toBe(false);
  });
  
  test('should adjust scroll chunking based on content density', async () => {
    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 1.0, false, 0, 0, false,
    );
    jest.runAllTimers();
    await flushMicrotasks();
    await scrollPromise;

    expect(document.documentElement.scrollBy).toHaveBeenCalledWith(
      expect.objectContaining({
        left: 0,
        behavior: 'auto',
      })
    );
    expect(document.documentElement.scrollBy.mock.calls[0][0].top).toBeCloseTo(128);
  });

  test('should detect completion if scroll boundary is hit', async () => {
    // Re-assign the mock for this test
    document.documentElement.scrollBy = jest.fn(() => {
      // scrollTop remains unchanged
    });

    const scrollPromise = scrollingFunction(
      '#target-element',
      0, 0, 0, false, 0, 0, false,
    );
    jest.runAllTimers();
    await flushMicrotasks();
    const result = await scrollPromise;

    expect(result.isComplete).toBe(true);
  });


  // --- Expanded Coverage: Nested Scrolling ---

  describe('Nested Scrolling (getScrollableParent)', () => {
    let container, nestedTarget;

    beforeEach(() => {
      // *** START FIX ***
      // Aggressively restore all mocks to prevent state leakage from main beforeEach
      jest.restoreAllMocks();
      
      // We must re-mock Math.random and rAF for this test block
      jest.spyOn(Math, 'random').mockReturnValue(0.5);
      jest.spyOn(window, 'requestAnimationFrame').mockImplementation(cb => setTimeout(cb, 16));
      // *** END FIX ***
      
      // Setup DOM
      document.body.innerHTML = `
        <div id="scroll-container" style="height: 400px; width: 400px; overflow: auto;">
          <div style="height: 1500px; width: 1500px;">
            <div id="nested-target" style="margin-top: 850px; margin-left: 600px;">Target</div>
          </div>
        </div>
      `;
      container = document.getElementById('scroll-container');
      nestedTarget = document.getElementById('nested-target');

      // Mock container properties
      Object.defineProperties(container, {
        scrollTop: { value: 0, writable: true },
        scrollLeft: { value: 0, writable: true },
        clientHeight: { value: 400 },
        clientWidth: { value: 400 },
        scrollHeight: { value: 1500 },
        scrollWidth: { value: 1500 },
        isConnected: { value: true },
      });

      // *** START FIX ***
      // Assign mocks DIRECTLY to the instances
      // 1. Mock container.scrollBy
      container.scrollBy = jest.fn((options) => {
        container.scrollTop += options.top || 0;
        container.scrollLeft += options.left || 0;
      });
      
      // 2. Mock document.documentElement.scrollBy (so we can check it's NOT called)
      document.documentElement.scrollBy = jest.fn();
      
      // 3. Mock getComputedStyle for the NESTED case
      jest.spyOn(window, 'getComputedStyle').mockImplementation((el) => {
        if (el === container) return { overflowY: 'auto', overflowX: 'auto', display: 'block', visibility: 'visible' };
        if (el === document.documentElement) return { overflow: 'visible', display: 'block', visibility: 'visible' };
        return { display: 'block', overflow: 'visible', visibility: 'visible' };
      });
      // *** END FIX ***

      // Mock Bounding Rects
      jest.spyOn(container, 'getBoundingClientRect').mockReturnValue({ top: 50, left: 50, bottom: 450, right: 450 });
      jest.spyOn(nestedTarget, 'getBoundingClientRect').mockReturnValue({ top: 900, left: 650, bottom: 950, right: 700 });
    });

    test('should scroll nested container vertically and horizontally', async () => {
      const scrollPromise = scrollingFunction('#nested-target', 0, 0, 0, false, 0, 0, false);
      
      jest.runAllTimers();
      await flushMicrotasks();
      const result = await scrollPromise;

      expect(container.scrollBy).toHaveBeenCalledWith({ top: 520, left: 320, behavior: 'smooth' });
      
      // This assertion will now pass
      expect(document.documentElement.scrollBy).not.toHaveBeenCalled();
      
      expect(result.verticalDelta).toBeCloseTo(650);
      expect(result.horizontalDelta).toBeCloseTo(400);
    });
  });

  // --- Expanded Coverage: Content Density ---

  describe('Content Density Estimation', () => {

    beforeEach(() => {
        // *** START FIX ***
        // This block also needs its own mocks.
        jest.restoreAllMocks();
        jest.spyOn(Math, 'random').mockReturnValue(0.5);
        jest.spyOn(window, 'requestAnimationFrame').mockImplementation(cb => setTimeout(cb, 16));

        // Mock document.documentElement.scrollBy (functional)
        document.documentElement.scrollBy = jest.fn((options) => {
          if (typeof options === 'object' && options !== null) {
            document.documentElement.scrollTop += options.top || 0;
            document.documentElement.scrollLeft += options.left || 0;
          }
        });
        
        // Mock getComputedStyle for the DENSITY case
        jest.spyOn(window, 'getComputedStyle').mockImplementation((el) => {
            if (el.id === 'hidden-display') return { display: 'none', visibility: 'visible' };
            if (el.id === 'hidden-visibility') return { display: 'block', visibility: 'hidden' };
            if (el.id === 'visible') return { display: 'block', visibility: 'visible' };
            if (el === document.documentElement) return { overflowY: 'scroll', display: 'block', visibility: 'visible' };
            return { display: 'block', visibility: 'visible' };
        });
        // *** END FIX ***
    });

    test('should calculate low density for sparse content', async () => {
      document.body.innerHTML = `<div>Sparse Text</div><div id="target">T</div>`;
      const target = document.getElementById('target');
      // Must mock getBoundingClientRect for the target
      jest.spyOn(target, 'getBoundingClientRect').mockReturnValue({ top: 2000, bottom: 2100 });
      
      // Re-mock document properties since we restored all
      Object.defineProperties(document.documentElement, {
         scrollHeight: { value: 4000, writable: true, configurable: true },
         clientHeight: { value: 800, writable: true, configurable: true },
      });

      const scrollPromise = scrollingFunction('#target', 0, 0, 0, false, 0, 0, false);
      jest.runAllTimers();
      await flushMicrotasks();
      const result = await scrollPromise;

      expect(result.contentDensity).toBeCloseTo(11 / 3000);
    });

    test('should calculate high density and cap at 1.5', async () => {
        document.body.innerHTML = `<p>${'a'.repeat(6000)}</p><div id="target">T</div>`;
        const target = document.getElementById('target');
        jest.spyOn(target, 'getBoundingClientRect').mockReturnValue({ top: 2000, bottom: 2100 });
        
        // Re-mock document properties since we restored all
        Object.defineProperties(document.documentElement, {
           scrollHeight: { value: 4000, writable: true, configurable: true },
           clientHeight: { value: 800, writable: true, configurable: true },
        });

        const scrollPromise = scrollingFunction('#target', 0, 0, 0, false, 0, 0, false);
        jest.runAllTimers();
        await flushMicrotasks();
        const result = await scrollPromise;

        expect(result.contentDensity).toBe(1.5);
    });

    test('should ignore scripts, styles, hidden elements', async () => {
        document.body.innerHTML = `
            <div id="visible">Visible Text</div>
            <script>const a = "${'ignore'.repeat(500)}";</script>
            <style>body { color: red; /* ${'ignore'.repeat(500)} */ }</style>
            <div id="hidden-display">${'ignore'.repeat(500)}</div>
            <div id="hidden-visibility">${'ignore'.repeat(500)}</div>
            <div id="target">T</div>
        `;
        const target = document.getElementById('target');
        jest.spyOn(target, 'getBoundingClientRect').mockReturnValue({ top: 2000, bottom: 2100 });

        // Re-mock document properties since we restored all
        Object.defineProperties(document.documentElement, {
           scrollHeight: { value: 4000, writable: true, configurable: true },
           clientHeight: { value: 800, writable: true, configurable: true },
        });
        
        const scrollPromise = scrollingFunction('#target', 0, 0, 0, false, 0, 0, false);
        jest.runAllTimers();
        await flushMicrotasks();
        const result = await scrollPromise;

        expect(result.contentDensity).toBeCloseTo(12 / 3000);
    });
  });

  // --- Expanded Coverage: Stabilization ---

  describe('Scroll Stabilization', () => {
    // Note: These tests will use the mocks from the main `beforeEach` block
    
    test('should wait until scroll position stops changing', async () => {
      const scrollPromise = scrollingFunction(
        '#target-element',
        0, 0, 0, false, 0, 0, false
      );
      jest.runAllTimers();
      await flushMicrotasks();
      await scrollPromise;
    });

    test('should resolve stabilization if timeout is hit (1000ms for scrollBy)', async () => {
        // Re-assign mock for this test
        document.documentElement.scrollBy = jest.fn((options) => {
            // Don't update scroll position
        });

        jest.spyOn(window, 'requestAnimationFrame').mockImplementation(cb => {
            document.documentElement.scrollTop += 1; // constantly change
            setTimeout(cb, 16);
        });
        
        const scrollPromise = scrollingFunction(
            '#target-element',
            0, 0, 0, false, 0, 0, false,
        );

        let resolved = false;
        scrollPromise.then(() => { resolved = true; });

        // Advance timers *just past* the 1000ms timeout
        jest.advanceTimersByTime(1001);
        await flushMicrotasks();
        
        expect(resolved).toBe(true);
    });

    test('should resolve stabilization immediately if element disconnects', async () => {
        // *** START FIX ***
        // This test needs the nested setup, so we must re-mock everything
        jest.restoreAllMocks();
        jest.spyOn(Math, 'random').mockReturnValue(0.5);
        // *** END FIX ***
        
        document.body.innerHTML = `<div id="scroll-container" style="overflow: auto; height: 100px;">
                                     <div style="height: 1000px;">
                                       <div id="nested-target" style="margin-top: 500px;">Target</div>
                                     </div>
                                   </div>`;
        const container = document.getElementById('scroll-container');
        const nestedTarget = document.getElementById('nested-target');
        
        Object.defineProperties(container, {
             scrollTop: { value: 0, writable: true }, scrollLeft: { value: 0, writable: true },
             clientHeight: { value: 100 }, clientWidth: { value: 100 },
             scrollHeight: { value: 1000 }, scrollWidth: { value: 100 },
             isConnected: { value: true, writable: true, configurable: true },
        });
        
        // *** START FIX ***
        // Assign mocks directly to instances
        container.scrollBy = jest.fn();
        document.documentElement.scrollBy = jest.fn();
        // *** END FIX ***
        
        jest.spyOn(window, 'getComputedStyle').mockImplementation(el => (el === container) ? { overflowY: 'auto' } : { overflow: 'visible' });
        
        jest.spyOn(nestedTarget, 'getBoundingClientRect').mockReturnValue({ top: 500, bottom: 550 });
        jest.spyOn(container, 'getBoundingClientRect').mockReturnValue({ top: 10, bottom: 110 });

        let frame = 0;
        jest.spyOn(window, 'requestAnimationFrame').mockImplementation(cb => {
            if (frame === 1) {
                Object.defineProperty(container, 'isConnected', { value: false });
            }
            frame++;
            setTimeout(cb, 16);
        });
        
        const scrollPromise = scrollingFunction('#nested-target', 0, 0, 0, false, 0, 0, false);
        
        jest.runAllTimers();
        await flushMicrotasks();
        await scrollPromise;
        // Test passes if await resolves
    });
  });
});